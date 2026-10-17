// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "udp_client_sweep.h"

#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dump_family(int fd, uint8_t family, uint8_t *bitmap) {
    struct {
        struct nlmsghdr header;
        struct inet_diag_req_v2 request;
    } message;
    memset(&message, 0, sizeof(message));
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    message.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    message.request.sdiag_family = family;
    message.request.sdiag_protocol = IPPROTO_UDP;
    message.request.idiag_states = ~0U;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    ssize_t sent;
    do {
        sent = sendto(fd, &message, sizeof(message), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(message)) return -1;

    /* inet_diag_msg replies are small; 32 KiB holds a few hundred per read. */
    static __thread uint8_t buffer[32768] __attribute__((aligned(NLMSG_ALIGNTO)));
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
            if (header->nlmsg_type == NLMSG_DONE) return 0;
            if (header->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *error = NLMSG_DATA(header);
                errno = error->error < 0 ? -error->error : EIO;
                return -1;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
                continue;
            }
            const struct inet_diag_msg *socket_info = NLMSG_DATA(header);
            uint16_t port = ntohs(socket_info->id.idiag_sport);
            bitmap[port >> 3U] |= (uint8_t)(1U << (port & 7U));
        }
    }
}

int bpf2socks_udp_collect_local_ports(uint8_t *bitmap) {
    if (bitmap == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(bitmap, 0, BPF2SOCKS_UDP_PORT_BITMAP_BYTES);
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) return -1;
    /* IPv4 clients may also live on dual-stack IPv6 sockets, so dump both. */
    int result = dump_family(fd, AF_INET, bitmap);
    if (result == 0) result = dump_family(fd, AF_INET6, bitmap);
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}
