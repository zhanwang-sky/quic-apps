//
//  quic_common.hpp
//  quic-apps
//
//  Created by 冀宸 on 2020/7/22.
//  Copyright © 2020 冀宸. All rights reserved.
//

#ifndef quic_common_hpp
#define quic_common_hpp

#include "quiche.h"

namespace quic_apps {

constexpr std::size_t max_dgram_size = 65535;
constexpr std::size_t max_encap_size = 1350;

constexpr std::size_t max_conn_id_len = QUICHE_MAX_CONN_ID_LEN;
constexpr std::size_t local_conn_id_len = 0x10;

uint8_t *gen_scid(uint8_t *__restrict, std::size_t);

} /* quic_apps */

#endif /* quic_common_hpp */
