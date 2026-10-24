// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "core/token.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"

#include <errno.h>
#include <stdatomic.h>
#include <string.h>

/* Hash maps gained LOOKUP_AND_DELETE in Linux 5.14; GKI 5.10 rejects it. */
static atomic_bool lookup_and_delete_unsupported;

bool bpf2socks_token_key_is_loopback(const struct bpf2socks_token_key *key) {
    if (key->family == AF_INET) return key->client_addr[0] == 127U;
    static const uint8_t loopback6[16] = {[15] = 1U};
    return key->family == AF_INET6 && memcmp(key->client_addr, loopback6, sizeof(loopback6)) == 0;
}

int bpf2socks_token_lookup(int map_fd, const struct bpf2socks_token_key *key, struct bpf2socks_original_dst *out) {
    if (map_fd < 0 || key == NULL || out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    return bpf2socks_bpf_map_lookup(map_fd, key, out);
}

int bpf2socks_token_take(
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
        if (bpf2socks_bpf_map_lookup_and_delete(map_fd, key, out) == 0) return 0;
        if (errno == ENOENT) return -1;
        atomic_store_explicit(&lookup_and_delete_unsupported, true, memory_order_relaxed);
    }
    if (bpf2socks_token_lookup(map_fd, key, out) < 0) return -1;
    if (bpf2socks_bpf_map_delete(map_fd, key) < 0) {
        *delete_failed = true;
        errno = 0;
    }
    return 0;
}

static int lookup_full_client(
    int map_fd,
    const struct bpf2socks_token_key *key,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_token_lookup_trace *trace) {
    ++trace->full_client_attempts;
    if (bpf2socks_token_lookup(map_fd, key, original) != 0) return -1;
    trace->matched_mode = BPF2SOCKS_TOKEN_LOOKUP_FULL_CLIENT;
    return 0;
}

static int lookup_zero_client(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_token_lookup_trace *trace) {
    struct bpf2socks_token_key zero_key = *full_key;
    zero_key.client_port = 0U;
    memset(zero_key.client_addr, 0, sizeof(zero_key.client_addr));
    ++trace->zero_client_attempts;
    if (bpf2socks_token_lookup(map_fd, &zero_key, original) != 0) return -1;
    trace->matched_mode = BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT;
    return 0;
}

int bpf2socks_token_lookup_udp(
    int map_fd,
    const struct bpf2socks_token_key *full_key,
    enum bpf2socks_token_lookup_mode preference,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_token_lookup_trace *trace) {
    if (map_fd < 0 || full_key == NULL || original == NULL || trace == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(original, 0, sizeof(*original));
    memset(trace, 0, sizeof(*trace));

    /* A new local session would otherwise always miss the full key first. */
    if (preference == BPF2SOCKS_TOKEN_LOOKUP_UNKNOWN &&
        bpf2socks_token_key_is_loopback(full_key)) {
        preference = BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT;
    }
    if (preference == BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT) {
        if (lookup_zero_client(map_fd, full_key, original, trace) == 0) return 0;
        return lookup_full_client(map_fd, full_key, original, trace);
    }
    if (lookup_full_client(map_fd, full_key, original, trace) == 0) return 0;
    return lookup_zero_client(map_fd, full_key, original, trace);
}
