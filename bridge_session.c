// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge_internal.h"

#include <stdint.h>

uint32_t bpf2socks_hash_bytes(const void *data, size_t len) {
    const uint8_t *ptr = data;
    uint32_t hash = 2166136261U;
    for (size_t i = 0; i < len; ++i) {
        hash ^= ptr[i];
        hash *= 16777619U;
    }
    return hash;
}

uint32_t bpf2socks_udp_effective_idle_timeout(
    uint32_t configured_timeout,
    uint32_t default_timeout) {
    uint32_t timeout = configured_timeout != 0U ? configured_timeout : default_timeout;
    if (timeout == 0U) timeout = 120U;
    return timeout;
}
