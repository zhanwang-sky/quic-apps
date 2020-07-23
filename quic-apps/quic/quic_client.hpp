//
//  quic_client.hpp
//  quic-apps
//
//  Created by 冀宸 on 2020/7/22.
//  Copyright © 2020 冀宸. All rights reserved.
//

#ifndef quic_client_hpp
#define quic_client_hpp

#include <array>
#include <functional>
#include <ostream>
#include <string>
#include <boost/asio.hpp>
#include "quic_common.hpp"

namespace quic_apps {

class quic_client {
public:
    typedef enum {
        ESTABLISHED,
        DATA_RECEIVED,
        DISCONNECTED,
    } callback_reason;

    using callback_type
        = std::function<void(quic_client&, callback_reason, uint64_t, std::size_t, bool)>;

    quic_client(boost::asio::io_context &io,
                const std::string &host,
                const std::string &port,
                const boost::asio::mutable_buffer &user_buf,
                callback_type &&user_cb,
                std::ostream *dbg_os = nullptr,
                quiche_config *qconfig = nullptr);

    ~quic_client();

    ssize_t send(uint64_t stream_id, const boost::asio::const_buffer &buf, bool fin);

private:
    inline void
    call_user_cb(callback_reason reason,
                 uint64_t stream_id, std::size_t nbytes, bool fin)
    {
        m_user_cb_invoked = true;
        m_user_cb(*this, reason, stream_id, nbytes, fin);
        m_user_cb_invoked = false;
    }

    void flush_egress();
    void close_conn();

    void receive_cb(const boost::system::error_code&, std::size_t);
    void timeout_cb(const boost::system::error_code&);

    boost::asio::ip::udp::socket        m_socket;
    boost::asio::steady_timer           m_timer;
    boost::asio::mutable_buffer         m_user_buf;
    callback_type                       m_user_cb;
    std::array<uint8_t, max_dgram_size> m_rx_buf;
    std::array<uint8_t, max_encap_size> m_tx_buf;
    std::ostream  *m_dbg_os;
    quiche_config *m_qconfig = nullptr;
    quiche_conn   *m_qconn   = nullptr;
    bool m_user_cb_invoked  = false;
    bool m_conn_established = false;
};

} /* quic_apps */

#endif /* quic_client_hpp */
