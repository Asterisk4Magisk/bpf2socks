// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_ORIGINAL_DST_H
#define BPF2SOCKS_CORE_ORIGINAL_DST_H

#include "bpf2socks.h"

#include <stdint.h>
#include <sys/socket.h>

/*
 * The original destination a socket or cmsg reports, rejected when it is a
 * token address or (IPv6) unspecified/loopback, which are never real peers.
 */
int bpf2socks_original_dst_from_sockaddr(
    const struct sockaddr_storage *addr,
    const struct bpf2socks_runtime_config *config,
    uint8_t protocol,
    struct bpf2socks_original_dst *original);
int bpf2socks_original_dst_from_cmsg(
    const struct cmsghdr *cmsg,
    const struct bpf2socks_runtime_config *config,
    uint8_t protocol,
    struct bpf2socks_original_dst *original);

int bpf2socks_original_dst_to_sockaddr(const struct bpf2socks_original_dst *src, struct bpf2socks_sockaddr *dst);

#endif
