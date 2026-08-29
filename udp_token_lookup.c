// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "udp_token_lookup.h"

#include <errno.h>
#include <string.h>

static int lookup_full_client(
    int map_fd,
    const struct bpf2socks_token_key *key,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_udp_token_lookup_trace *trace) {
    ++trace->full_client_attempts;
    if (bpf2socks_token_lookup(map_fd, key, original) != 0) return -1;
    trace->matched_mode = BPF2SOCKS_UDP_TOKEN_LOOKUP_FULL_CLIENT;
    return 0;
}

static int lookup_zero_client(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_udp_token_lookup_trace *trace) {
    struct bpf2socks_token_key zero_key = *full_key;
    zero_key.client_port = 0U;
    memset(zero_key.client_addr, 0, sizeof(zero_key.client_addr));
    ++trace->zero_client_attempts;
    if (bpf2socks_token_lookup(map_fd, &zero_key, original) != 0) return -1;
    trace->matched_mode = BPF2SOCKS_UDP_TOKEN_LOOKUP_ZERO_CLIENT;
    return 0;
}

int bpf2socks_udp_token_lookup_adaptive(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    enum bpf2socks_udp_token_lookup_mode preference,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_udp_token_lookup_trace *trace) {
    if (map_fd < 0 || full_key == NULL || original == NULL || trace == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(original, 0, sizeof(*original));
    memset(trace, 0, sizeof(*trace));

    if (preference == BPF2SOCKS_UDP_TOKEN_LOOKUP_ZERO_CLIENT) {
        if (lookup_zero_client(map_fd, full_key, original, trace) == 0) return 0;
        return lookup_full_client(map_fd, full_key, original, trace);
    }
    if (lookup_full_client(map_fd, full_key, original, trace) == 0) return 0;
    return lookup_zero_client(map_fd, full_key, original, trace);
}
