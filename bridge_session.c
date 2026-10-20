// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bridge_internal.h"

#include <arpa/inet.h>
#include <netinet/in.h>
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

bool bpf2socks_sockaddr_storage_is_loopback(const struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        return (ntohl(in->sin_addr.s_addr) >> 24U) == 127U;
    }
    if (addr->ss_family == AF_INET6) {
        const struct in6_addr *in6 = &((const struct sockaddr_in6 *)addr)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(in6) || (IN6_IS_ADDR_V4MAPPED(in6) && in6->s6_addr[12] == 127U);
    }
    return false;
}
