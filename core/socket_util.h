// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_SOCKET_UTIL_H
#define BPF2SOCKS_CORE_SOCKET_UTIL_H

#include "bpf2socks.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

/* A socket buffer size within 4 KiB..4 MiB; 0 selects fallback. */
uint32_t bpf2socks_socket_clamp_buffer(uint32_t requested, uint32_t fallback);
void bpf2socks_socket_tune_buffers(int fd, uint32_t recv_size, uint32_t send_size);
void bpf2socks_socket_tune_tcp_buffers(int fd, const struct bpf2socks_runtime_config *config);
/* TCP_NODELAY and TCP_QUICKACK; upstream sockets also try TCP Fast Open. */
void bpf2socks_socket_tune_tcp_latency(int fd, bool upstream);
void bpf2socks_socket_enable_fastopen_listener(int fd);
int bpf2socks_socket_connect(int fd, const struct sockaddr *addr, socklen_t addr_len);
int bpf2socks_socket_accept4(int fd, struct sockaddr *peer, socklen_t *peer_len, int flags);
bool bpf2socks_sockaddr_is_loopback(const struct sockaddr_storage *addr);

#endif
