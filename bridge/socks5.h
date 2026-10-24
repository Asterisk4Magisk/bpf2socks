// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_SOCKS5_H
#define BPF2SOCKS_BRIDGE_SOCKS5_H

#include "bpf2socks.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

int bpf2socks_socks5_resolve_server(const char *host, uint16_t port, struct sockaddr_storage *addr, socklen_t *addr_len);

// Non-blocking SOCKS5 helpers for DNS channel state machine.
// Returns fd with non-blocking connect; errno=EINPROGRESS means pending.
int bpf2socks_socks5_connect_nonblock(
    const struct sockaddr *addr,
    socklen_t addr_len);
/* ATYP, address and port of addr; 0 with errno when it does not fit or is not IP. */
size_t bpf2socks_socks5_write_addr(uint8_t *out, size_t out_cap, const struct bpf2socks_sockaddr *addr);
/*
 * Total length of a SOCKS5 reply (VER REP RSV ATYP BND.ADDR BND.PORT) from
 * its first len bytes: 0 while more are needed, SIZE_MAX when it is malformed
 * or reports a failure.
 */
size_t bpf2socks_socks5_reply_length(const uint8_t *reply, size_t len);
/* CONNECT request for dst; 0 with errno when it does not fit out_cap. */
size_t bpf2socks_socks5_build_connect_request(
    uint8_t *out,
    size_t out_cap,
    const struct bpf2socks_sockaddr *dst);
// Build SOCKS5 hello/greeting (3 bytes). Returns length written.
size_t bpf2socks_socks5_build_hello(uint8_t *out, size_t out_cap);
// Validate 2-byte hello reply. 0=ok, -1=fail.
int bpf2socks_socks5_parse_hello_reply(const uint8_t *reply, size_t len);
// Build SOCKS5 UDP ASSOCIATE request. Returns total length written.
size_t bpf2socks_socks5_build_udp_associate_request(uint8_t *out, size_t out_cap);
// Parse SOCKS5 bound address reply (4+addr+port). 0=ok, -1=fail, 1=need more data.
int bpf2socks_socks5_parse_bound_addr(
    const uint8_t *buf, size_t len, size_t *consumed,
    struct sockaddr_storage *bound, socklen_t *bound_len);
// Replace unspecified relay addr with socks addr if needed. 0=ok, -1=fail.
int bpf2socks_socks5_replace_unspecified_relay(
    const struct sockaddr *socks_addr,
    struct sockaddr_storage *relay_addr, socklen_t *relay_addr_len);
int bpf2socks_socks5_udp_sendmmsg(
    int udp_fd,
    const struct sockaddr *relay_addr,
    socklen_t relay_addr_len,
    const struct bpf2socks_udp_msg *messages,
    unsigned int count);
/*
 * Returns the number of datagrams dequeued. A truncated or malformed datagram
 * only sets that message's error, so one bad reply never discards the batch.
 */
int bpf2socks_socks5_udp_recvmmsg(
    int udp_fd,
    struct bpf2socks_udp_msg *messages,
    unsigned int count,
    uint8_t *packet_buffer,
    size_t packet_stride);

#endif
