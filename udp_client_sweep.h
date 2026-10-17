// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_UDP_CLIENT_SWEEP_H
#define BPF2SOCKS_UDP_CLIENT_SWEEP_H

#include <stdbool.h>
#include <stdint.h>

/* One bit per UDP port. */
#define BPF2SOCKS_UDP_PORT_BITMAP_BYTES (65536U / 8U)

/*
 * Fills bitmap with the local ports of every IPv4 and IPv6 UDP socket in this
 * network namespace (sock_diag dump). Returns -1 with errno when the dump
 * fails, in which case the bitmap content is unspecified.
 */
int bpf2socks_udp_collect_local_ports(uint8_t *bitmap);

static inline bool bpf2socks_udp_port_bitmap_has(const uint8_t *bitmap, uint16_t port) {
    return (bitmap[port >> 3U] & (uint8_t)(1U << (port & 7U))) != 0U;
}

#endif
