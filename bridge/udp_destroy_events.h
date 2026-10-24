// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_UDP_DESTROY_EVENTS_H
#define BPF2SOCKS_BRIDGE_UDP_DESTROY_EVENTS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One bit per UDP port. */
#define BPF2SOCKS_UDP_PORT_BITMAP_BYTES (65536U / 8U)

static inline bool bpf2socks_udp_port_bitmap_has(const uint8_t *bitmap, uint16_t port) {
    return (bitmap[port >> 3U] & (uint8_t)(1U << (port & 7U))) != 0U;
}

static inline void bpf2socks_udp_port_bitmap_set(uint8_t *bitmap, uint16_t port) {
    bitmap[port >> 3U] |= (uint8_t)(1U << (port & 7U));
}

/*
 * Non-blocking NETLINK_SOCK_DIAG socket joined to the IPv4 and IPv6 UDP
 * destroy groups: the kernel multicasts one inet_diag_msg per UDP socket it
 * frees, to every such socket, so each worker gets its own copy.
 */
int bpf2socks_udp_destroy_events_open(void);

/*
 * Reads every queued notification and sets each destroyed socket's local port
 * in port_bitmap. Returns the notifications read. *lost is set when the kernel
 * dropped notifications because the receive queue was full (ENOBUFS).
 */
size_t bpf2socks_udp_destroy_events_drain(int fd, uint8_t *port_bitmap, bool *lost);

/*
 * 1 when some IPv4 or IPv6 UDP socket in this namespace still has local port
 * `port`, 0 when none has, -1 with errno when the sock_diag query failed.
 */
int bpf2socks_udp_destroy_events_port_open(uint16_t port);

/* Checks that a closed UDP socket is reported; 0 on success, -1 with message. */
int bpf2socks_udp_destroy_events_probe(char *message, size_t message_size);

#endif
