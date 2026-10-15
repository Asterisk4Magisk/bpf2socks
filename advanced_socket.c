// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bridge_internal.h"

#include <arpa/inet.h>
#include <asm/unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif
#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
#ifndef TCP_QUICKACK
#define TCP_QUICKACK 12
#endif
#ifndef TCP_CORK
#define TCP_CORK 3
#endif
static void set_probe_message(char *message, size_t message_size, const char *feature, int error) {
    if (message == NULL || message_size == 0U) return;
    snprintf(message, message_size, "%s is unavailable: errno=%d", feature, error);
}

static int probe_setsockopt(
    const char *feature,
    int family,
    int type,
    int protocol,
    int level,
    int optname,
    int value,
    char *message,
    size_t message_size) {
    int fd = socket(family, type | SOCK_CLOEXEC, protocol);
    if (fd < 0) {
        set_probe_message(message, message_size, feature, errno);
        return -1;
    }
    int rc = setsockopt(fd, level, optname, &value, sizeof(value));
    int saved = errno;
    close(fd);
    if (rc != 0) {
        errno = saved;
        set_probe_message(message, message_size, feature, errno);
        return -1;
    }
    return 0;
}

int bpf2socks_advanced_socket_probe(char *message, size_t message_size) {
    if (message != NULL && message_size > 0U) message[0] = '\0';
    if (probe_setsockopt(
            "TCP_FASTOPEN_CONNECT",
            AF_INET,
            SOCK_STREAM,
            0,
            IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT,
            1,
            message,
            message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_FASTOPEN", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_FASTOPEN, 5, message, message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_QUICKACK", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_QUICKACK, 1, message, message_size) < 0) {
        return -1;
    }
    if (probe_setsockopt("TCP_CORK", AF_INET, SOCK_STREAM, 0, IPPROTO_TCP, TCP_CORK, 1, message, message_size) < 0) {
        return -1;
    }
    if (message != NULL && message_size > 0U) snprintf(message, message_size, "ok");
    return 0;
}

void bpf2socks_bridge_tune_tcp_advanced(int fd, bool upstream) {
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
int bpf2socks_bridge_connect(int fd, const struct sockaddr *addr, socklen_t addr_len) {
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
int bpf2socks_bridge_accept4(int fd, int flags) {
#ifdef __NR_accept4
    return (int)syscall(__NR_accept4, fd, NULL, NULL, flags);
#else
    return accept4(fd, NULL, NULL, flags);
#endif
}

void bpf2socks_bridge_enable_tcp_fastopen_listener(int fd) {
    int backlog = 4096;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &backlog, sizeof(backlog));
}
