// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bridge_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define BPF2SOCKS_SOCKS5_UDP_HEADER_CAP 22U

static size_t socks5_write_addr(uint8_t *out, const struct bpf2socks_sockaddr *addr);

int bpf2socks_resolve_tcp_addr(const char *host, uint16_t port, struct sockaddr_storage *addr, socklen_t *addr_len) {
    if (host == NULL || addr == NULL || addr_len == NULL) {
        errno = EINVAL;
        return -1;
    }
    char port_buf[16];
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    snprintf(port_buf, sizeof(port_buf), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port_buf, &hints, &result) != 0) return -1;

    int rc = -1;
    for (struct addrinfo *it = result; it != NULL; it = it->ai_next) {
        if ((size_t)it->ai_addrlen > sizeof(*addr)) continue;
        memset(addr, 0, sizeof(*addr));
        memcpy(addr, it->ai_addr, it->ai_addrlen);
        *addr_len = (socklen_t)it->ai_addrlen;
        rc = 0;
        break;
    }
    freeaddrinfo(result);
    if (rc < 0) errno = ENOENT;
    return rc;
}

int bpf2socks_socks5_connect_nonblock(
    const struct sockaddr *addr,
    socklen_t addr_len) {
    if (addr == NULL || addr_len == 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    bpf2socks_bridge_tune_tcp_advanced(fd, true);
    if (bpf2socks_bridge_connect(fd, addr, addr_len) == 0) return fd;
    if (errno == EINPROGRESS) return fd;
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

size_t bpf2socks_socks5_build_hello(uint8_t *out, size_t out_cap) {
    if (out == NULL || out_cap < 3U) return 0U;
    out[0] = 0x05;
    out[1] = 0x01;
    out[2] = 0x00;
    return 3U;
}

int bpf2socks_socks5_parse_hello_reply(const uint8_t *reply, size_t len) {
    if (reply == NULL || len < 2U) {
        errno = EAGAIN;
        return 1;
    }
    if (reply[0] != 0x05 || reply[1] != 0x00) return -1;
    return 0;
}

size_t bpf2socks_socks5_build_udp_associate_request(uint8_t *out, size_t out_cap) {
    if (out == NULL || out_cap < (4U + 16U + 2U)) return 0U;
    struct bpf2socks_sockaddr any_addr;
    memset(&any_addr, 0, sizeof(any_addr));
    any_addr.family = AF_INET;
    any_addr.port = 0;
    size_t len = 0;
    out[len++] = 0x05;
    out[len++] = 0x03;
    out[len++] = 0x00;
    len += socks5_write_addr(out + len, &any_addr);
    return len;
}

int bpf2socks_socks5_parse_bound_addr(
    const uint8_t *buf, size_t len, size_t *consumed,
    struct sockaddr_storage *bound, socklen_t *bound_len) {
    if (buf == NULL || consumed == NULL || bound == NULL || bound_len == NULL) {
        errno = EINVAL;
        return -1;
    }
    *consumed = 0U;
    if (len < 4U) {
        errno = EAGAIN;
        return 1;
    }
    if (buf[0] != 0x05 || buf[1] != 0x00) return -1;
    memset(bound, 0, sizeof(*bound));
    if (buf[3] == 0x01) {
        if (len < 4U + 4U + 2U) {
            errno = EAGAIN;
            return 1;
        }
        struct sockaddr_in *addr = (struct sockaddr_in *)bound;
        addr->sin_family = AF_INET;
        memcpy(&addr->sin_addr, buf + 4U, 4);
        memcpy(&addr->sin_port, buf + 8U, 2);
        *bound_len = sizeof(*addr);
        *consumed = 4U + 4U + 2U;
        return 0;
    }
    if (buf[3] == 0x04) {
        if (len < 4U + 16U + 2U) {
            errno = EAGAIN;
            return 1;
        }
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)bound;
        addr->sin6_family = AF_INET6;
        memcpy(&addr->sin6_addr, buf + 4U, 16);
        memcpy(&addr->sin6_port, buf + 20U, 2);
        *bound_len = sizeof(*addr);
        *consumed = 4U + 16U + 2U;
        return 0;
    }
    if (buf[3] == 0x03) {
        if (len < 4U + 1U) {
            errno = EAGAIN;
            return 1;
        }
        uint8_t n = buf[4U];
        if (n == 0U) return -1;
        if (len < 4U + 1U + (size_t)n + 2U) {
            errno = EAGAIN;
            return 1;
        }
        char host[256];
        memcpy(host, buf + 5U, n);
        host[n] = '\0';
        char port_buf[8];
        uint16_t reply_port = ((uint16_t)buf[5U + n] << 8) | buf[6U + n];
        snprintf(port_buf, sizeof(port_buf), "%u", reply_port);
        struct addrinfo hints;
        struct addrinfo *result = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host, port_buf, &hints, &result) != 0 || result == NULL) return -1;
        if ((size_t)result->ai_addrlen > sizeof(*bound)) {
            freeaddrinfo(result);
            return -1;
        }
        memcpy(bound, result->ai_addr, result->ai_addrlen);
        *bound_len = (socklen_t)result->ai_addrlen;
        freeaddrinfo(result);
        *consumed = 4U + 1U + (size_t)n + 2U;
        return 0;
    }
    return -1;
}

static size_t socks5_write_addr(uint8_t *out, const struct bpf2socks_sockaddr *addr) {
    size_t len = 0;
    if (addr->family == AF_INET) {
        out[len++] = 0x01;
        memcpy(out + len, addr->addr, 4);
        len += 4U;
    } else if (addr->family == AF_INET6) {
        out[len++] = 0x04;
        memcpy(out + len, addr->addr, 16);
        len += 16U;
    } else {
        return 0;
    }
    out[len++] = (uint8_t)(addr->port >> 8);
    out[len++] = (uint8_t)(addr->port & 0xffU);
    return len;
}

int bpf2socks_socks5_replace_unspecified_relay(
    const struct sockaddr *socks_addr,
    socklen_t socks_addr_len,
    struct sockaddr_storage *relay_addr,
    socklen_t *relay_addr_len) {
    (void)socks_addr_len;
    if (socks_addr == NULL || relay_addr == NULL || relay_addr_len == NULL) return -1;
    if (relay_addr->ss_family == AF_INET) {
        struct sockaddr_in *relay4 = (struct sockaddr_in *)relay_addr;
        if (relay4->sin_addr.s_addr != htonl(INADDR_ANY)) return 0;
        if (socks_addr->sa_family != AF_INET) return 0;
        const struct sockaddr_in *socks4 = (const struct sockaddr_in *)socks_addr;
        relay4->sin_addr = socks4->sin_addr;
        *relay_addr_len = sizeof(*relay4);
        return 0;
    }
    if (relay_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *relay6 = (struct sockaddr_in6 *)relay_addr;
        if (!IN6_IS_ADDR_UNSPECIFIED(&relay6->sin6_addr)) return 0;
        if (socks_addr->sa_family != AF_INET6) return 0;
        const struct sockaddr_in6 *socks6 = (const struct sockaddr_in6 *)socks_addr;
        relay6->sin6_addr = socks6->sin6_addr;
        *relay_addr_len = sizeof(*relay6);
    }
    return 0;
}

int bpf2socks_socks5_udp_sendmmsg(
    int udp_fd,
    const struct sockaddr *relay_addr,
    socklen_t relay_addr_len,
    const struct bpf2socks_udp_msg *messages,
    unsigned int count) {
    if (udp_fd < 0 || messages == NULL || count == 0U) return -1;

    struct mmsghdr vec[count];
    struct iovec iov[count * 2U];
    uint8_t headers[count][BPF2SOCKS_SOCKS5_UDP_HEADER_CAP];
    memset(vec, 0, sizeof(vec));
    for (unsigned int i = 0; i < count; ++i) {
        if (messages[i].payload == NULL) {
            errno = EINVAL;
            return -1;
        }
        size_t header_len = 0;
        headers[i][header_len++] = 0x00;
        headers[i][header_len++] = 0x00;
        headers[i][header_len++] = 0x00;
        size_t addr_len = socks5_write_addr(headers[i] + header_len, &messages[i].addr);
        if (addr_len == 0U || header_len + addr_len > sizeof(headers[i])) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        header_len += addr_len;

        iov[i * 2U].iov_base = headers[i];
        iov[i * 2U].iov_len = header_len;
        iov[i * 2U + 1U].iov_base = messages[i].payload;
        iov[i * 2U + 1U].iov_len = messages[i].payload_len;

        vec[i].msg_hdr.msg_name = (void *)relay_addr;
        vec[i].msg_hdr.msg_namelen = relay_addr != NULL ? relay_addr_len : 0U;
        vec[i].msg_hdr.msg_iov = &iov[i * 2U];
        vec[i].msg_hdr.msg_iovlen = 2U;
    }

    return sendmmsg(udp_fd, vec, count, 0);
}

/* Returns 0, or the errno-style reason the SOCKS5 UDP datagram is unusable. */
static int parse_socks5_udp_datagram(uint8_t *packet, size_t len, struct bpf2socks_udp_msg *message) {
    if (len < 4U || packet[0] != 0x00 || packet[1] != 0x00 || packet[2] != 0x00) return EPROTO;
    size_t pos = 3U;
    if (packet[pos] == 0x01) {
        if (len < pos + 1U + 4U + 2U) return EPROTO;
        message->addr.family = AF_INET;
        ++pos;
        memcpy(message->addr.addr, packet + pos, 4);
        pos += 4U;
    } else if (packet[pos] == 0x04) {
        if (len < pos + 1U + 16U + 2U) return EPROTO;
        message->addr.family = AF_INET6;
        ++pos;
        memcpy(message->addr.addr, packet + pos, 16);
        pos += 16U;
    } else if (packet[pos] == 0x03) {
        /*
         * A server that maps a reply back to a domain destination names the
         * domain, not the peer. Keep only the port (AF_UNSPEC); the caller
         * matches it to a binding it already has.
         */
        ++pos;
        if (len < pos + 1U || len < pos + 1U + packet[pos] + 2U) return EPROTO;
        message->addr.family = AF_UNSPEC;
        pos += 1U + packet[pos];
    } else {
        return EAFNOSUPPORT;
    }
    message->addr.port = ((uint16_t)packet[pos] << 8) | packet[pos + 1U];
    pos += 2U;
    message->payload = packet + pos;
    message->payload_len = len - pos;
    return 0;
}

int bpf2socks_socks5_udp_recvmmsg(
    int udp_fd,
    struct bpf2socks_udp_msg *messages,
    unsigned int count,
    uint8_t *packet_buffer,
    size_t packet_stride) {
    if (udp_fd < 0 || messages == NULL || count == 0U || packet_buffer == NULL ||
        packet_stride <= BPF2SOCKS_SOCKS5_UDP_HEADER_CAP) {
        errno = EINVAL;
        return -1;
    }

    struct mmsghdr vec[count];
    struct iovec iov[count];
    for (unsigned int i = 0; i < count; ++i) {
        iov[i].iov_base = packet_buffer + packet_stride * i;
        iov[i].iov_len = packet_stride;
        vec[i].msg_hdr = (struct msghdr){.msg_iov = &iov[i], .msg_iovlen = 1U};
        vec[i].msg_len = 0U;
    }

    int received = recvmmsg(udp_fd, vec, count, MSG_DONTWAIT, NULL);
    if (received <= 0) return received;

    for (int i = 0; i < received; ++i) {
        memset(&messages[i], 0, sizeof(messages[i]));
        if ((vec[i].msg_hdr.msg_flags & MSG_TRUNC) != 0 || vec[i].msg_len > packet_stride) {
            messages[i].error = EMSGSIZE;
            continue;
        }
        messages[i].error = parse_socks5_udp_datagram(
            packet_buffer + packet_stride * (size_t)i,
            vec[i].msg_len,
            &messages[i]);
    }
    return received;
}
