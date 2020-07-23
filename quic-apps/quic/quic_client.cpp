//
//  quic_client.cpp
//  quic-apps
//
//  Created by 冀宸 on 2020/7/22.
//  Copyright © 2020 冀宸. All rights reserved.
//

#include <exception>
#include "quic_client.hpp"

using std::string;

namespace asio = boost::asio;
namespace chrono = asio::chrono;
using asio::ip::udp;

using quic_apps::quic_client;

quic_client::quic_client(asio::io_context &io,
                         const string &host,
                         const string &port,
                         const asio::mutable_buffer &user_buf,
                         callback_type &&user_cb,
                         std::ostream *dbg_os,
                         quiche_config *qconfig):
    m_socket(io),
    m_timer(io),
    m_user_buf(user_buf),
    m_user_cb(user_cb),
    m_dbg_os(dbg_os)
{
    uint8_t scid[local_conn_id_len];
    const char *err_msg;
    udp::resolver resolver(io);
    udp::endpoint remote_ep = *resolver.resolve(host, port).begin();

    // for convenience
    m_socket.connect(remote_ep);

    if (!qconfig) {
        char protos[] = "\x05hq-29";
        m_qconfig = quiche_config_new(QUICHE_PROTOCOL_VERSION);
        if (!m_qconfig) {
            err_msg = "failed to create quiche_config";
            goto ERR_QCONFIG;
        }
        quiche_config_set_application_protos(m_qconfig,
            (uint8_t *) protos, sizeof(protos) - 1);
        quiche_config_set_max_idle_timeout(m_qconfig, 5000);
        quiche_config_set_max_udp_payload_size(m_qconfig, max_dgram_size);
        quiche_config_set_initial_max_data(m_qconfig, 10000000);
        quiche_config_set_initial_max_stream_data_bidi_local(m_qconfig, 1000000);
        quiche_config_set_initial_max_stream_data_uni(m_qconfig, 1000000);
        quiche_config_set_initial_max_streams_bidi(m_qconfig, 100);
        quiche_config_set_initial_max_streams_uni(m_qconfig, 100);
        quiche_config_set_disable_active_migration(m_qconfig, true);
    }

    gen_scid(scid, sizeof(scid));
    m_qconn = quiche_connect(host.c_str(), scid, sizeof(scid), qconfig ? qconfig : m_qconfig);
    if (!m_qconn) {
        err_msg = "failed to create quiche_conn";
        goto ERR_QCONN;
    }

    m_socket.non_blocking(true); // for non-block sending
    m_socket.async_receive(asio::buffer(m_rx_buf),
                           std::bind(&quic_client::receive_cb, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));

    flush_egress();

    if (m_dbg_os) {
        (*m_dbg_os) << "> (quic_client " << this << ") constructed\n";
    }

    return;

ERR_QCONN:
    if (!qconfig && m_qconfig) {
        quiche_config_free(m_qconfig);
    }
ERR_QCONFIG:
    throw std::runtime_error(err_msg);
}

quic_client::~quic_client()
{
    quiche_conn_free(m_qconn);
    if (m_qconfig) {
        quiche_config_free(m_qconfig);
    }

    if (m_dbg_os) {
        (*m_dbg_os) << "> (quic_client " << this << ") destructed\n";
    }
}

ssize_t
quic_client::send(uint64_t stream_id, const asio::const_buffer &buf, bool fin)
{
    ssize_t rc_bytes;
    rc_bytes = quiche_conn_stream_send(m_qconn,
                                       stream_id,
                                       (const uint8_t *) buf.data(),
                                       buf.size(),
                                       fin);

    if (rc_bytes < 0) {
        if (m_dbg_os) {
            (*m_dbg_os) << "! (quic_client " << this << ") "
                << "stream_send error(stream_id " << stream_id << ","
                << "len " << buf.size() << ","
                << "fin " << (fin ? "true" : "false") << ")"
                << ": " << rc_bytes << "\n";
        }
    }

    if (!m_user_cb_invoked && rc_bytes >= 0) {
        flush_egress();
    }

    return rc_bytes;
}

void
quic_client::flush_egress()
{
    unsigned packets_being_sent = 0;

    while (1) {
        ssize_t rc_bytes;

        rc_bytes = quiche_conn_send(m_qconn, m_tx_buf.data(), m_tx_buf.size());
        if (rc_bytes < 0) {
            if (rc_bytes != QUICHE_ERR_DONE) {
                if (m_dbg_os) {
                    (*m_dbg_os) << "! (quic_client " << this << ") "
                        << "failed to create packet (" << rc_bytes << ")\n";
                }
            }
            break;
        }

        boost::system::error_code ec;
        m_socket.send(asio::buffer(m_tx_buf.data(), rc_bytes), 0, ec);
        if (ec) {
            if (m_dbg_os) {
                (*m_dbg_os) << "! (quic_client " << this << ") "
                    << "failed to send packet (" << ec.message() << ")\n";
            }
            continue;
        }

        ++packets_being_sent;
    }

    if (m_dbg_os) {
        (*m_dbg_os) << "> (quic_client " << this << ") "
            << packets_being_sent << " packets being sent\n";
    }

    auto timeoutns = quiche_conn_timeout_as_nanos(m_qconn);
    m_timer.expires_after(chrono::nanoseconds(timeoutns));
    m_timer.async_wait(std::bind(&quic_client::timeout_cb, this,
                                 std::placeholders::_1));
}

void
quic_client::close_conn()
{
    m_conn_established = false;

    call_user_cb(DISCONNECTED, UINT64_MAX, 0, true);

    if (m_dbg_os) {
        quiche_stats stats;
        quiche_conn_stats(m_qconn, &stats);
        (*m_dbg_os) << "> (quic_client " << this << ") "
            << "connection closed,"
            << " recv=" << stats.recv
            << " sent=" << stats.sent
            << " lost=" << stats.lost
            << " rtt=" << stats.rtt << "ns"
            << " cwnd=" << stats.cwnd << "\n";
    }

    m_socket.cancel();
    m_timer.cancel();
}

void
quic_client::receive_cb(const boost::system::error_code &ec,
                        std::size_t nbytes)
{
    if (m_dbg_os) {
        (*m_dbg_os) << "> (quic_client " << this << ") "
            << nbytes << " bytes received (" << ec.message() << ")\n";
    }

    if (ec == boost::system::errc::operation_canceled) {
        return;
    }

    if (!ec) {
        ssize_t rc_bytes;

        do {
            rc_bytes = quiche_conn_recv(m_qconn, m_rx_buf.data(), nbytes);
            if (rc_bytes < 0) {
                if (m_dbg_os) {
                    (*m_dbg_os) << "* (quic_client " << this << ") "
                        << "failed to process packet (" << rc_bytes << ")\n";
                }
                break;
            }

            if (quiche_conn_is_closed(m_qconn)) {
                close_conn();
                return;
            }

            if (quiche_conn_is_established(m_qconn)) {
                quiche_stream_iter *stream_iter;
                uint64_t            stream_id;

                if (!m_conn_established) {
                    m_conn_established = true;
                    call_user_cb(ESTABLISHED, 0, 0, false);
                }

                stream_iter = quiche_conn_readable(m_qconn);

                while (quiche_stream_iter_next(stream_iter, &stream_id)) {
                    bool    fin;
                    ssize_t recv_len;

                    do {
                        fin = false;
                        recv_len = quiche_conn_stream_recv(m_qconn,
                                                           stream_id,
                                                           (uint8_t *) m_user_buf.data(),
                                                           m_user_buf.size(),
                                                           &fin);
                        if (recv_len < 0) {
                            if (m_dbg_os) {
                                (*m_dbg_os) << "! (quic_client " << this << ") "
                                    << "stream_recv error(stream_id " << stream_id << ")"
                                    << ": " << recv_len << "\n";
                            }
                            break;
                        }

                        call_user_cb(DATA_RECEIVED, stream_id, recv_len, fin);
                    } while ((std::size_t) recv_len == m_user_buf.size());
                }

                quiche_stream_iter_free(stream_iter);
            }
        } while (0);
    }

    m_socket.async_receive(asio::buffer(m_rx_buf),
                           std::bind(&quic_client::receive_cb, this,
                                     std::placeholders::_1,
                                     std::placeholders::_2));

    if (!ec) {
        flush_egress();
    }
}

void
quic_client::timeout_cb(const boost::system::error_code &ec)
{
    if (m_dbg_os) {
        (*m_dbg_os) << "> (quic_client " << this << ") "
            << "timer expired (" << ec.message() << ")\n";
    }

    if (!ec) {
        quiche_conn_on_timeout(m_qconn);
        flush_egress();
        if (quiche_conn_is_closed(m_qconn)) {
            close_conn();
        }
    }
}
