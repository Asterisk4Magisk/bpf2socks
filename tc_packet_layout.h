// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_TC_PACKET_LAYOUT_H
#define BPF2SOCKS_TC_PACKET_LAYOUT_H

#include <linux/types.h>

struct tcp_header_min {
    __be16 source;
    __be16 destination;
    __be32 sequence;
    __be32 acknowledgement;
    __be16 flags;
    __be16 window;
    __sum16 checksum;
};

struct udp_header_min {
    __be16 source;
    __be16 destination;
    __be16 length;
    __sum16 checksum;
};

#endif
