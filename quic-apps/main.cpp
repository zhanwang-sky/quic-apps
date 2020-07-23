//
//  main.cpp
//  quic-apps
//
//  Created by 冀宸 on 2020/7/22.
//  Copyright © 2020 冀宸. All rights reserved.
//

#include <cstdlib>
#include <iostream>
#include "quic_client.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::array;

namespace asio = boost::asio;

using quic_apps::quic_client;

int main(int argc, const char *argv[])
{
    if (argc != 3) {
        cerr << "usage: " << argv[0] << " host port\n";
        exit(1);
    }

    array<uint8_t, 4096> buf;

    auto cb = [&buf](quic_client &cli, quic_client::callback_reason reason,
                     uint64_t stream_id, std::size_t nbytes, bool fin) {
        switch (reason) {
        case quic_client::ESTABLISHED:
            cout << "@@@ connection established @@@\n";
            break;

        case quic_client::DATA_RECEIVED:
            cout << "@@@ stream " << stream_id << ", len " << nbytes << (fin ? ", fin" : "") << " @@@\n";
            cout.put('`').write((const char *) buf.data(), nbytes).put('`').put('\n');
            break;

        default:
            cout << "@@@ connection closed @@@\n";
            break;
        }
    };

    quiche_enable_debug_logging(
        [](const char *line, void *unused){ cout << line << endl; },
        NULL
    );

    asio::io_context io;
    try {
        quic_client c(io, argv[1], argv[2], asio::buffer(buf), cb, &cerr);
        io.run();
    } catch (std::exception &e) {
        cerr << "exception caught: " << e.what() << endl;
    }

    return 0;
}
