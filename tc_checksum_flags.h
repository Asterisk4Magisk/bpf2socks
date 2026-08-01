// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_TC_CHECKSUM_FLAGS_H
#define BPF2SOCKS_TC_CHECKSUM_FLAGS_H

#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>

#ifndef BPF_F_MARK_MANGLED_0
#define BPF_F_MARK_MANGLED_0 (1ULL << 5)
#endif

static __inline __attribute__((always_inline)) __u64
bpf2socks_l4_common_flags(bool is_udp, __u64 size) {
    return size | (is_udp ? BPF_F_MARK_MANGLED_0 : 0U);
}

static __inline __attribute__((always_inline)) __u64
bpf2socks_l4_address_flags(bool is_udp, __u64 size) {
    return bpf2socks_l4_common_flags(is_udp, size) | BPF_F_PSEUDO_HDR;
}

static __inline __attribute__((always_inline)) __u64
bpf2socks_l4_port_flags(bool is_udp, __u64 size) {
    return bpf2socks_l4_common_flags(is_udp, size);
}

#endif
