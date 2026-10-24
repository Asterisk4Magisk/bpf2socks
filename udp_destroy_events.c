// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "udp_destroy_events.h"

#include "bpf2socks.h"

#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif

#define DESTROY_EVENTS_PROBE_WAIT_MILLISECONDS 200

/* Notifications and dump replies are small; 32 KiB holds a few hundred per read. */
static __thread uint8_t buffer[32768] __attribute__((aligned(NLMSG_ALIGNTO)));

int bpf2socks_udp_destroy_events_open(void) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_SOCK_DIAG);
    if (fd < 0) return -1;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    local.nl_groups = (1U << (SKNLGRP_INET_UDP_DESTROY - 1U)) | (1U << (SKNLGRP_INET6_UDP_DESTROY - 1U));
    if (bind(fd, (const struct sockaddr *)&local, sizeof(local)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    /* Bursts of closes (a resolver storm) queue faster than one wakeup drains. */
    int size = (int)BPF2SOCKS_UDP_DESTROY_EVENTS_RCVBUF;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, sizeof(size)) != 0) {
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    }
    return fd;
}

size_t bpf2socks_udp_destroy_events_drain(int fd, uint8_t *port_bitmap, bool *lost) {
    size_t count = 0U;
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (received < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                *lost = true;
                continue;
            }
            break;
        }
        size_t remaining = (size_t)received;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
                continue;
            }
            const struct inet_diag_msg *socket_info = NLMSG_DATA(header);
            bpf2socks_udp_port_bitmap_set(port_bitmap, ntohs(socket_info->id.idiag_sport));
            ++count;
        }
    }
    return count;
}

/* Dumps the family's UDP sockets bound to port; 1 if any, 0 if none, -1 on error. */
static int query_family(int fd, uint8_t family, uint16_t port) {
    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
        struct rtattr bytecode_attr;
        struct inet_diag_bc_op ops[2];
    } message;
    memset(&message, 0, sizeof(message));
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    message.request.sdiag_family = family;
    message.request.sdiag_protocol = IPPROTO_UDP;
    message.request.idiag_states = ~0U;
    message.bytecode_attr.rta_type = INET_DIAG_REQ_BYTECODE;
    message.bytecode_attr.rta_len = RTA_LENGTH(sizeof(message.ops));
    /* Source port equals `port`: accept by jumping to the end, reject past it. */
    message.ops[0].code = INET_DIAG_BC_S_EQ;
    message.ops[0].yes = sizeof(message.ops);
    message.ops[0].no = sizeof(message.ops) + 4U;
    message.ops[1].no = port;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent;
    do {
        sent = sendto(fd, &message, sizeof(message), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(message)) return -1;

    int found = 0;
    for (;;) {
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) {
            if (received == 0) errno = EIO;
            return -1;
        }
        size_t remaining = (size_t)received;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer;
             NLMSG_OK(header, remaining);
             header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_type == NLMSG_DONE) return found;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error = NLMSG_DATA(header);
                errno = error->error < 0 ? -error->error : EIO;
                return -1;
            }
            if (header->nlmsg_type == SOCK_DIAG_BY_FAMILY) found = 1;
        }
    }
}

int bpf2socks_udp_port_has_socket(uint16_t port) {
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return -1;
    /* IPv4 clients may also live on dual-stack IPv6 sockets, so query both. */
    int result = query_family(fd, AF_INET, port);
    if (result == 0) result = query_family(fd, AF_INET6, port);
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}

static uint64_t probe_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0U;
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}

int bpf2socks_udp_destroy_events_probe(char *message, size_t message_size) {
    int fd = bpf2socks_udp_destroy_events_open();
    if (fd < 0) {
        snprintf(message, message_size, "subscribe failed: errno=%d", errno);
        return -1;
    }
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t addr_len = sizeof(addr);
    if (udp < 0 || bind(udp, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        getsockname(udp, (struct sockaddr *)&addr, &addr_len) != 0) {
        snprintf(message, message_size, "test socket failed: errno=%d", errno);
        if (udp >= 0) close(udp);
        close(fd);
        return -1;
    }
    uint16_t port = ntohs(addr.sin_port);
    close(udp);

    static uint8_t bitmap[BPF2SOCKS_UDP_PORT_BITMAP_BYTES];
    memset(bitmap, 0, sizeof(bitmap));
    bool lost = false;
    bool seen = false;
    uint64_t deadline = probe_now_ms() + DESTROY_EVENTS_PROBE_WAIT_MILLISECONDS;
    while (!seen) {
        uint64_t now = probe_now_ms();
        if (now >= deadline) break;
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, (int)(deadline - now)) <= 0) continue;
        (void)bpf2socks_udp_destroy_events_drain(fd, bitmap, &lost);
        seen = bpf2socks_udp_port_bitmap_has(bitmap, port);
    }
    close(fd);
    if (!seen) {
        snprintf(message, message_size, "no notification for a closed socket within %d ms",
            DESTROY_EVENTS_PROBE_WAIT_MILLISECONDS);
        return -1;
    }
    message[0] = '\0';
    return 0;
}
