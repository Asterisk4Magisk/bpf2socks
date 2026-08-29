// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_UDP_TOKEN_LOOKUP_H
#define BPF2SOCKS_UDP_TOKEN_LOOKUP_H

#include "bpf2socks.h"

#include <stdint.h>

enum bpf2socks_udp_token_lookup_mode {
    BPF2SOCKS_UDP_TOKEN_LOOKUP_UNKNOWN = 0,
    BPF2SOCKS_UDP_TOKEN_LOOKUP_FULL_CLIENT,
    BPF2SOCKS_UDP_TOKEN_LOOKUP_ZERO_CLIENT,
};

struct bpf2socks_udp_token_lookup_trace {
    enum bpf2socks_udp_token_lookup_mode matched_mode;
    uint8_t full_client_attempts;
    uint8_t zero_client_attempts;
};

int bpf2socks_udp_token_lookup_adaptive(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    enum bpf2socks_udp_token_lookup_mode preference,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_udp_token_lookup_trace *trace);

#endif
