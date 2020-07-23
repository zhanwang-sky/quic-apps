//
//  quic_common.cpp
//  quic-apps
//
//  Created by 冀宸 on 2020/7/22.
//  Copyright © 2020 冀宸. All rights reserved.
//

#include <chrono>
#include <random>
#include "quic_common.hpp"

uint8_t*
quic_apps::gen_scid(uint8_t *__restrict scid, std::size_t scid_len)
{
    std::default_random_engine e(
        (unsigned) std::chrono::steady_clock::now().time_since_epoch().count()
    );
    std::uniform_int_distribution<uint8_t> r;
    for (decltype(scid_len) i = 0; i < scid_len; ++i) {
        scid[i] = r(e);
    }
    return scid;
}
