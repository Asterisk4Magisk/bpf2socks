// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "core/socket_util.h"
#include "bpf2socks.h"
#include "core/compat.h"

#include <arpa/inet.h>
#include <asm/unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>
#include <unistd.h>

uint32_t bpf2socks_socket_clamp_buffer(uint32_t requested, uint32_t fallback) {
    uint32_t value = requested == 0U ? fallback : requested;
    if (value < 4096U) value = 4096U;
    if (value > 4194304U) value = 4194304U;
    return value;
}

/*
 * tcpBufferSize 0 leaves TCP buffers to kernel autotuning. An explicit size
 * locks them (SOCK_RCVBUF_LOCK), which caps the window on high-RTT hotspot
 * links; accepted sockets inherit the listener's lock, so listeners follow
 * the same rule.
 */
void bpf2socks_socket_tune_tcp_buffers(int fd, const struct bpf2socks_runtime_config *config) {
    if (config == NULL || config->tcp_buffer_size == 0U) return;
    uint32_t size = bpf2socks_socket_clamp_buffer(config->tcp_buffer_size, config->tcp_buffer_size);
    bpf2socks_socket_tune_buffers(fd, size, size);
}

void bpf2socks_socket_tune_buffers(int fd, uint32_t recv_size, uint32_t send_size) {
    if (recv_size > 0U) {
        int value = (int)recv_size;
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
    }
    if (send_size > 0U) {
        int value = (int)send_size;
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value));
    }
}

void bpf2socks_socket_tune_tcp_latency(int fd, bool upstream) {
    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
    if (upstream) {
        (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &one, sizeof(one));
    }
}

static bool sockaddr_is_loopback(const struct sockaddr *addr, socklen_t addr_len) {
    if (addr->sa_family == AF_INET && addr_len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        return (ntohl(in->sin_addr.s_addr) >> 24) == 127U;
    }
    if (addr->sa_family == AF_INET6 && addr_len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr);
    }
    return false;
}

/*
 * Bionic routes connect() through libnetd_client, which performs a blocking
 * FwmarkServer round trip per call. A loopback SOCKS upstream needs no
 * network selection mark, so issue the syscall directly for it and keep the
 * libc path for every other destination.
 */
int bpf2socks_socket_connect(int fd, const struct sockaddr *addr, socklen_t addr_len) {
#ifdef __NR_connect
    if (addr != NULL && sockaddr_is_loopback(addr, addr_len)) {
        return (int)syscall(__NR_connect, fd, addr, addr_len);
    }
#endif
    return connect(fd, addr, addr_len);
}

/*
 * Bionic's accept4() also performs a blocking FwmarkServer round trip
 * (ON_ACCEPT) that only adds permission and billing bits to the mark. Replies
 * from the bridge's accepted sockets route over loopback or the hotspot's
 * local network, neither of which depends on those bits.
 */
int bpf2socks_socket_accept4(int fd, struct sockaddr *peer, socklen_t *peer_len, int flags) {
#ifdef __NR_accept4
    return (int)syscall(__NR_accept4, fd, peer, peer_len, flags);
#else
    return accept4(fd, peer, peer_len, flags);
#endif
}

void bpf2socks_socket_enable_fastopen_listener(int fd) {
    int backlog = 4096;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog));
}

bool bpf2socks_sockaddr_is_loopback(const struct sockaddr_storage *addr) {
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
