// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"

#include <errno.h>
#include <stdatomic.h>
#include <string.h>

/* Hash maps gained LOOKUP_AND_DELETE in Linux 5.14; GKI 5.10 rejects it. */
static atomic_bool lookup_and_delete_unsupported;

bool bpf2socks_token_key_client_is_loopback(const struct bpf2socks_token_key *key) {
    if (key->family == AF_INET) return key->client_addr[0] == 127U;
    static const uint8_t loopback6[16] = {[15] = 1U};
    return key->family == AF_INET6 && memcmp(key->client_addr, loopback6, sizeof(loopback6)) == 0;
}

int bpf2socks_token_lookup(int map_fd, const struct bpf2socks_token_key *key, struct bpf2socks_original_dst *out) {
    if (map_fd < 0 || key == NULL || out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    return bpf2socks_lookup_map(map_fd, key, out);
}

int bpf2socks_tcp_token_take(
    int map_fd,
    const struct bpf2socks_token_key *key,
    struct bpf2socks_original_dst *out,
    bool *delete_failed) {
    if (map_fd < 0 || key == NULL || out == NULL || delete_failed == NULL) {
        errno = EINVAL;
        return -1;
    }
    *delete_failed = false;
    if (!atomic_load_explicit(&lookup_and_delete_unsupported, memory_order_relaxed)) {
        memset(out, 0, sizeof(*out));
        if (bpf2socks_lookup_and_delete_map(map_fd, key, out) == 0) return 0;
        if (errno == ENOENT) return -1;
        atomic_store_explicit(&lookup_and_delete_unsupported, true, memory_order_relaxed);
    }
    if (bpf2socks_token_lookup(map_fd, key, out) < 0) return -1;
    if (bpf2socks_delete_map(map_fd, key) < 0) {
        *delete_failed = true;
        errno = 0;
    }
    return 0;
}
