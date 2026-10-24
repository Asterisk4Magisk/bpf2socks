// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/udp_budget.h"
#include "bridge/udp_downlink_queue.h"
#include "bridge/udp_internal.h"
#include "core/compat.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Replies to UDP clients: reply sockets, raw sends, batching and queued downlink. */

uint32_t bpf2socks_udp_checksum_add_bytes(uint32_t sum, const void *data, size_t len) {
    const uint8_t *ptr = data;
    while (len > 1U) {
        sum += ((uint32_t)ptr[0] << 8) | ptr[1];
        ptr += 2;
        len -= 2U;
    }
    if (len == 1U) {
        sum += (uint32_t)ptr[0] << 8;
    }
    return sum;
}

uint16_t bpf2socks_udp_checksum_fold(uint32_t sum) {
    while ((sum >> 16U) != 0U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return (uint16_t)~sum;
}

static uint16_t udp_ipv4_checksum(
    uint32_t source_addr,
    uint32_t destination_addr,
    const struct bpf2socks_udp_header *udp,
    const uint8_t *payload,
    size_t payload_len) {
    struct {
        uint32_t source_addr;
        uint32_t destination_addr;
        uint8_t zero;
        uint8_t protocol;
        uint16_t length;
    } pseudo;
    pseudo.source_addr = source_addr;
    pseudo.destination_addr = destination_addr;
    pseudo.zero = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.length = udp->len;

    uint32_t sum = 0;
    sum = bpf2socks_udp_checksum_add_bytes(sum, &pseudo, sizeof(pseudo));
    sum = bpf2socks_udp_checksum_add_bytes(sum, udp, sizeof(*udp));
    sum = bpf2socks_udp_checksum_add_bytes(sum, payload, payload_len);
    uint16_t result = bpf2socks_udp_checksum_fold(sum);
    return result == 0U ? 0xffffU : result;
}

static uint16_t udp_ipv6_checksum(
    const uint8_t source_addr[16],
    const uint8_t destination_addr[16],
    const struct bpf2socks_udp_header *udp,
    const uint8_t *payload,
    size_t payload_len) {
    struct {
        uint8_t source_addr[16];
        uint8_t destination_addr[16];
        uint32_t length;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo;
    memcpy(pseudo.source_addr, source_addr, 16);
    memcpy(pseudo.destination_addr, destination_addr, 16);
    pseudo.length = htonl((uint32_t)(sizeof(*udp) + payload_len));
    memset(pseudo.zero, 0, sizeof(pseudo.zero));
    pseudo.next_header = IPPROTO_UDP;

    uint32_t sum = 0;
    sum = bpf2socks_udp_checksum_add_bytes(sum, &pseudo, sizeof(pseudo));
    sum = bpf2socks_udp_checksum_add_bytes(sum, udp, sizeof(*udp));
    sum = bpf2socks_udp_checksum_add_bytes(sum, payload, payload_len);
    uint16_t result = bpf2socks_udp_checksum_fold(sum);
    return result == 0U ? 0xffffU : result;
}

int bpf2socks_udp_raw_send4(
    int fd,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    const uint8_t *payload,
    size_t payload_len) {
    if (session == NULL || binding == NULL ||
        session->client_addr.ss_family != AF_INET ||
        binding->original_dst.family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    const size_t udp_len = sizeof(struct bpf2socks_udp_header) + payload_len;
    const size_t ip_len = sizeof(struct iphdr) + udp_len;
    if (ip_len > UINT16_MAX || payload_len > BPF2SOCKS_UDP_BUFFER_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    uint8_t packet[sizeof(struct iphdr) + sizeof(struct bpf2socks_udp_header) + BPF2SOCKS_UDP_BUFFER_SIZE];
    memset(packet, 0, sizeof(struct iphdr) + sizeof(struct bpf2socks_udp_header));
    struct iphdr *ip = (struct iphdr *)packet;
    struct bpf2socks_udp_header *udp = (struct bpf2socks_udp_header *)(packet + sizeof(*ip));
    uint8_t *body = packet + sizeof(*ip) + sizeof(*udp);
    memcpy(body, payload, payload_len);

    const struct sockaddr_in *client = (const struct sockaddr_in *)&session->client_addr;
    uint32_t source_addr = 0;
    memcpy(&source_addr, binding->original_dst.addr, sizeof(source_addr));

    ip->version = 4;
    ip->ihl = sizeof(*ip) / 4U;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->tot_len = htons((uint16_t)ip_len);
    ip->id = htons((uint16_t)time(NULL));
    ip->saddr = source_addr;
    ip->daddr = client->sin_addr.s_addr;
    ip->check = htons(bpf2socks_udp_checksum_fold(bpf2socks_udp_checksum_add_bytes(0, ip, sizeof(*ip))));

    udp->source = htons(binding->original_dst.port);
    udp->dest = client->sin_port;
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0;
    udp->check = htons(udp_ipv4_checksum(ip->saddr, ip->daddr, udp, body, payload_len));

    ssize_t sent = sendto(fd, packet, ip_len, 0, (const struct sockaddr *)client, sizeof(*client));
    if (sent == (ssize_t)ip_len) return 0;
    if (sent >= 0) errno = EIO;
    return -1;
}

int bpf2socks_udp_raw_send6(
    int fd,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    const uint8_t *payload,
    size_t payload_len) {
    if (session == NULL || binding == NULL ||
        session->client_addr.ss_family != AF_INET6 ||
        binding->original_dst.family != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    const size_t udp_len = sizeof(struct bpf2socks_udp_header) + payload_len;
    const size_t ip_len = sizeof(struct ipv6hdr) + udp_len;
    if (udp_len > UINT16_MAX || payload_len > BPF2SOCKS_UDP_BUFFER_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    uint8_t packet[sizeof(struct ipv6hdr) + sizeof(struct bpf2socks_udp_header) + BPF2SOCKS_UDP_BUFFER_SIZE];
    memset(packet, 0, sizeof(struct ipv6hdr) + sizeof(struct bpf2socks_udp_header));
    struct ipv6hdr *ip = (struct ipv6hdr *)packet;
    struct bpf2socks_udp_header *udp = (struct bpf2socks_udp_header *)(packet + sizeof(*ip));
    uint8_t *body = packet + sizeof(*ip) + sizeof(*udp);
    memcpy(body, payload, payload_len);

    const struct sockaddr_in6 *client = (const struct sockaddr_in6 *)&session->client_addr;
    ip->version = 6;
    ip->payload_len = htons((uint16_t)udp_len);
    ip->nexthdr = IPPROTO_UDP;
    ip->hop_limit = 64;
    memcpy(&ip->saddr, binding->original_dst.addr, 16);
    memcpy(&ip->daddr, &client->sin6_addr, 16);

    udp->source = htons(binding->original_dst.port);
    udp->dest = client->sin6_port;
    udp->len = htons((uint16_t)udp_len);
    udp->check = 0;
    udp->check = htons(udp_ipv6_checksum(binding->original_dst.addr, client->sin6_addr.s6_addr, udp, body, payload_len));

    struct sockaddr_in6 destination = *client;
    // The socket uses IPPROTO_RAW; the UDP protocol is in the IPv6 header.
    destination.sin6_port = 0;
    ssize_t sent = sendto(fd, packet, ip_len, 0, (const struct sockaddr *)&destination, sizeof(destination));
    if (sent == (ssize_t)ip_len) return 0;
    if (sent >= 0) errno = EIO;
    return -1;
}

int bpf2socks_udp_raw_reply_socket_create4(void) {
    int fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one));
    return fd;
}

int bpf2socks_udp_raw_reply_socket_create6(void) {
    int fd = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &one, sizeof(one));
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one, sizeof(one));
    return fd;
}

static int create_udp4_client_reply_socket(const struct bpf2socks_sockaddr *original, bool *raw_socket) {
    if (original == NULL || original->family != AF_INET) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (raw_socket != NULL) *raw_socket = false;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, &one, sizeof(one)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(original->port);
    memcpy(&addr.sin_addr, original->addr, 4);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        fd = bpf2socks_udp_raw_reply_socket_create4();
        if (fd >= 0) {
            if (raw_socket != NULL) *raw_socket = true;
            return fd;
        }
        errno = saved;
        return -1;
    }
    return fd;
}

static int create_udp6_client_reply_socket(const struct bpf2socks_sockaddr *original, bool *raw_socket) {
    if (original == NULL || original->family != AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (raw_socket != NULL) *raw_socket = false;
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one, sizeof(one)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    (void)setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &one, sizeof(one));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(original->port);
    memcpy(&addr.sin6_addr, original->addr, 16);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        fd = bpf2socks_udp_raw_reply_socket_create6();
        if (fd >= 0) {
            if (raw_socket != NULL) *raw_socket = true;
            return fd;
        }
        errno = saved;
        return -1;
    }
    return fd;
}

int bpf2socks_udp_reply_socket_create(const struct bpf2socks_sockaddr *original, bool *raw_socket) {
    if (original == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (original->family == AF_INET) return create_udp4_client_reply_socket(original, raw_socket);
    if (original->family == AF_INET6) return create_udp6_client_reply_socket(original, raw_socket);
    errno = EAFNOSUPPORT;
    return -1;
}

static struct bpf2socks_udp_downlink_packet *alloc_downlink_packet(
    struct bpf2socks_udp_state *state,
    size_t payload_len) {
    if (state == NULL || state->pending_budget == NULL ||
        payload_len > SIZE_MAX - sizeof(struct bpf2socks_udp_downlink_packet)) {
        errno = ENOBUFS;
        return NULL;
    }
    size_t allocation_bytes = sizeof(struct bpf2socks_udp_downlink_packet) + payload_len;
    bool uses_read_reservation = state->downlink_read_reservation >= allocation_bytes;
    if (uses_read_reservation) {
        state->downlink_read_reservation -= allocation_bytes;
    } else if (bpf2socks_udp_budget_reserve(state->pending_budget, allocation_bytes) < 0) {
        return NULL;
    }
    struct bpf2socks_udp_downlink_packet *packet = malloc(allocation_bytes);
    if (packet == NULL) {
        if (uses_read_reservation) {
            state->downlink_read_reservation += allocation_bytes;
        } else {
            (void)bpf2socks_udp_budget_release(state->pending_budget, allocation_bytes);
        }
        errno = ENOMEM;
        return NULL;
    }
    memset(packet, 0, sizeof(*packet));
    packet->allocation_bytes = allocation_bytes;
    return packet;
}

size_t bpf2socks_udp_downlink_max_allocation(void) {
    return sizeof(struct bpf2socks_udp_downlink_packet) + BPF2SOCKS_UDP_BUFFER_SIZE;
}

void bpf2socks_udp_downlink_release_reservation(struct bpf2socks_udp_state *state) {
    if (state == NULL || state->downlink_read_reservation == 0U) return;
    size_t bytes = state->downlink_read_reservation;
    state->downlink_read_reservation = 0U;
    if (state->pending_budget != NULL) {
        (void)bpf2socks_udp_budget_release(state->pending_budget, bytes);
    }
}

int bpf2socks_udp_downlink_reserve_slots(struct bpf2socks_udp_state *state, uint32_t *batch) {
    if (state == NULL || state->pending_budget == NULL || batch == NULL || *batch == 0U ||
        state->downlink_read_reservation != 0U) {
        errno = EINVAL;
        return -1;
    }
    const size_t slot_bytes = bpf2socks_udp_downlink_max_allocation();
    uint32_t candidate = *batch;
    for (;;) {
        if ((size_t)candidate <= SIZE_MAX / slot_bytes) {
            size_t bytes = (size_t)candidate * slot_bytes;
            if (bpf2socks_udp_budget_reserve(state->pending_budget, bytes) == 0) {
                state->downlink_read_reservation = bytes;
                *batch = candidate;
                return 0;
            }
        } else {
            errno = EOVERFLOW;
        }
        if (candidate == 1U) return -1;
        candidate = (candidate + 1U) / 2U;
    }
}

static void release_downlink_packet(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_downlink_packet *packet) {
    if (state == NULL || packet == NULL) return;
    if (session != NULL && session->downlink_pending_count > 0U) {
        --session->downlink_pending_count;
    }
    if (packet->binding != NULL && packet->binding->downlink_pending_count > 0U) {
        --packet->binding->downlink_pending_count;
    }
    size_t allocation_bytes = packet->allocation_bytes;
    free(packet);
    if (state->pending_budget != NULL) {
        (void)bpf2socks_udp_budget_release(state->pending_budget, allocation_bytes);
    }
}

struct bpf2socks_udp_downlink_channel *bpf2socks_udp_downlink_find_channel(
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    int source_fd,
    bool use_pktinfo,
    bool raw) {
    if (session == NULL) return NULL;
    bool binding_source = binding != NULL && binding->reply_fd == source_fd && source_fd >= 0;
    for (struct bpf2socks_udp_downlink_channel *channel = session->downlink_channels;
        channel != NULL;
        channel = channel->next) {
        if (channel->source_binding == (binding_source ? binding : NULL) &&
            (!binding_source || channel->source_binding_generation == binding->reply_fd_generation) &&
            channel->source_fd == source_fd &&
            channel->use_pktinfo == use_pktinfo &&
            channel->raw == raw) {
            return channel;
        }
    }
    return NULL;
}

int bpf2socks_udp_downlink_set_paused(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    bool paused) {
    if (state == NULL || session == NULL || !session->used ||
        session->stage != BPF2SOCKS_UDP_SESSION_READY || session->udp_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (session->downlink_paused == paused) return 0;
    size_t index = bpf2socks_udp_session_index(state, session);
    if (index >= state->session_cap) {
        errno = EINVAL;
        return -1;
    }
    if (bpf2socks_udp_epoll_modify(
            state,
            session->udp_fd,
            &state->session_refs[index].relay,
            paused ? 0U : EPOLLIN) < 0) {
        return -1;
    }
    session->downlink_paused = paused;
    return 0;
}

void bpf2socks_udp_downlink_resume_budget_waiters(struct bpf2socks_udp_state *state) {
    // Resume DNS channels first — they are not tracked by the session waiter
    // tracker, so the early return below would skip them if no client session
    // is waiting at the same time.
    if (state != NULL && state->pending_budget != NULL) {
        const size_t slot_bytes = bpf2socks_udp_downlink_max_allocation();
        const size_t cap_bytes = state->pending_budget->cap_bytes;
        const size_t used_bytes = bpf2socks_udp_budget_used(state->pending_budget);
        if (cap_bytes >= slot_bytes && used_bytes <= cap_bytes - slot_bytes) {
            for (uint32_t i = 0U; i < BPF2SOCKS_DNS_CHANNELS_PER_WORKER; ++i) {
                struct bpf2socks_udp_dns_channel *channel = &state->dns_channels[i];
                if (!channel->relay_paused || channel->udp_fd < 0) continue;
                if (bpf2socks_udp_epoll_modify(
                        state, channel->udp_fd, &channel->relay_ref, EPOLLIN) < 0) {
                    continue;
                }
                channel->relay_paused = false;
            }
        }
    }
    if (state == NULL || state->pending_budget == NULL ||
        !bpf2socks_udp_downlink_waiter_tracker_has_waiters(&state->downlink_budget_waiters)) {
        return;
    }
    const size_t slot_bytes = bpf2socks_udp_downlink_max_allocation();
    const size_t cap_bytes = state->pending_budget->cap_bytes;
    const size_t used_bytes = bpf2socks_udp_budget_used(state->pending_budget);
    if (cap_bytes < slot_bytes || used_bytes > cap_bytes - slot_bytes) return;
    for (size_t i = 0U; i < state->session_cap; ++i) {
        struct bpf2socks_udp_client_session *session = &state->sessions[i];
        if (!session->used || !session->downlink_waiting_budget ||
            session->downlink_pending_count != 0U) {
            continue;
        }
        if (bpf2socks_udp_downlink_set_paused(state, session, false) == 0) {
            bpf2socks_udp_downlink_waiter_tracker_mark_ready(
                &state->downlink_budget_waiters,
                &session->downlink_waiting_budget);
        }
    }
}

static void unlink_downlink_channel(
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_downlink_channel *channel) {
    if (session == NULL || channel == NULL) return;
    struct bpf2socks_udp_downlink_channel **slot = &session->downlink_channels;
    while (*slot != NULL) {
        if (*slot == channel) {
            *slot = channel->next;
            channel->next = NULL;
            return;
        }
        slot = &(*slot)->next;
    }
}

static void retire_downlink_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_downlink_channel *channel,
    bool resume_session) {
    if (state == NULL || channel == NULL) return;
    unlink_downlink_channel(session, channel);
    bpf2socks_udp_epoll_remove(state, channel->fd);
    if (channel->fd >= 0) close(channel->fd);
    channel->fd = -1;
    while (channel->queue.head != NULL) {
        struct bpf2socks_udp_downlink_packet *packet = (struct bpf2socks_udp_downlink_packet *)
            bpf2socks_udp_downlink_queue_pop(&channel->queue);
        release_downlink_packet(state, session, packet);
    }
    channel->ref.session = NULL;
    channel->next = state->retired_downlink_channels;
    state->retired_downlink_channels = channel;
    if (resume_session && session != NULL && session->used &&
        session->downlink_pending_count == 0U && !session->downlink_waiting_budget &&
        session->downlink_paused) {
        (void)bpf2socks_udp_downlink_set_paused(state, session, false);
    }
}

void bpf2socks_udp_downlink_free_retired(struct bpf2socks_udp_state *state) {
    if (state == NULL) return;
    struct bpf2socks_udp_downlink_channel *channel = state->retired_downlink_channels;
    while (channel != NULL) {
        struct bpf2socks_udp_downlink_channel *next = channel->next;
        free(channel);
        channel = next;
    }
    state->retired_downlink_channels = NULL;
}

void bpf2socks_udp_downlink_release_session(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session) {
    if (state == NULL || session == NULL) return;
    while (session->downlink_channels != NULL) {
        retire_downlink_channel(state, session, session->downlink_channels, false);
    }
    session->downlink_pending_count = 0U;
    session->downlink_paused = false;
    bpf2socks_udp_downlink_waiter_tracker_mark_ready(
        &state->downlink_budget_waiters,
        &session->downlink_waiting_budget);
}

static struct bpf2socks_udp_downlink_channel *create_downlink_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    int source_fd,
    bool use_pktinfo,
    bool raw) {
    if (state == NULL || session == NULL || source_fd < 0) {
        errno = EINVAL;
        return NULL;
    }
    int fd = dup(source_fd);
    if (fd < 0) return NULL;
    struct bpf2socks_udp_downlink_channel *channel = calloc(1U, sizeof(*channel));
    if (channel == NULL) {
        int saved = errno;
        close(fd);
        errno = saved;
        return NULL;
    }
    channel->fd = fd;
    channel->source_fd = source_fd;
    if (binding != NULL && binding->reply_fd == source_fd) {
        channel->source_binding = binding;
        channel->source_binding_generation = binding->reply_fd_generation;
    }
    channel->use_pktinfo = use_pktinfo;
    channel->raw = raw;
    bpf2socks_udp_downlink_queue_init(&channel->queue);
    channel->ref.kind = BPF2SOCKS_UDP_FD_DOWNLINK;
    channel->ref.fd = fd;
    channel->ref.session = session;
    channel->ref.downlink = channel;
    if (bpf2socks_udp_epoll_add_events(state, fd, &channel->ref, EPOLLOUT) < 0) {
        int saved = errno;
        close(fd);
        free(channel);
        errno = saved;
        return NULL;
    }
    channel->next = session->downlink_channels;
    session->downlink_channels = channel;
    return channel;
}

int bpf2socks_udp_downlink_queue_packet(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_msg *message,
    int source_fd,
    bool use_pktinfo,
    bool raw) {
    if (state == NULL || session == NULL || binding == NULL || message == NULL || source_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_downlink_channel *channel =
        bpf2socks_udp_downlink_find_channel(session, binding, source_fd, use_pktinfo, raw);
    bool created = false;
    if (channel == NULL) {
        channel = create_downlink_channel(state, session, binding, source_fd, use_pktinfo, raw);
        if (channel == NULL) return -1;
        created = true;
    }
    struct bpf2socks_udp_downlink_packet *packet = alloc_downlink_packet(state, message->payload_len);
    if (packet == NULL) {
        if (created) retire_downlink_channel(state, session, channel, false);
        return -1;
    }
    packet->binding = binding;
    packet->payload_len = message->payload_len;
    memcpy(packet->payload, message->payload, message->payload_len);
    bpf2socks_udp_downlink_queue_push(&channel->queue, &packet->queue_node);
    ++session->downlink_pending_count;
    ++binding->downlink_pending_count;
    bpf2socks_udp_downlink_waiter_tracker_mark_ready(
        &state->downlink_budget_waiters,
        &session->downlink_waiting_budget);
    uint64_t now_ms = bpf2socks_now_ms();
    session->last_seen_ms = now_ms;
    binding->last_seen_ms = now_ms;
    bpf2socks_udp_lru_touch(state, session);
    bpf2socks_udp_binding_lru_touch(state, session, binding);
    return bpf2socks_udp_downlink_set_paused(state, session, true);
}

void bpf2socks_udp_downlink_batch_init(struct bpf2socks_udp_downlink_batch *batch) {
    memset(batch, 0, sizeof(*batch));
    batch->fd = -1;
}

static int fill_udp_downlink_pktinfo(
    struct msghdr *msg,
    char *control,
    size_t control_size,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding) {
    msg->msg_control = control;
    msg->msg_controllen = control_size;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
    if (cmsg == NULL) {
        errno = EMSGSIZE;
        return -1;
    }

    if (session->client_addr.ss_family == AF_INET6) {
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
        memset(pktinfo, 0, sizeof(*pktinfo));
        memcpy(&pktinfo->ipi6_addr, binding->token_addr, 16);
        msg->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    } else {
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
        struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsg);
        memset(pktinfo, 0, sizeof(*pktinfo));
        memcpy(&pktinfo->ipi_spec_dst, binding->token_addr, 4);
        msg->msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    }
    return 0;
}

static enum bpf2socks_udp_downlink_send_result send_downlink_channel_packet(
    struct bpf2socks_udp_downlink_channel *channel,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_downlink_packet *packet) {
    if (channel == NULL || session == NULL || packet == NULL || packet->binding == NULL) {
        errno = EINVAL;
        return BPF2SOCKS_UDP_DOWNLINK_SEND_FATAL;
    }
    if (channel->raw) {
        int sent = packet->binding->original_dst.family == AF_INET6
            ? bpf2socks_udp_raw_send6(
                  channel->fd,
                  session,
                  packet->binding,
                  packet->payload,
                  packet->payload_len)
            : bpf2socks_udp_raw_send4(
                  channel->fd,
                  session,
                  packet->binding,
                  packet->payload,
                  packet->payload_len);
        int send_errno = errno;
        return sent == 0
            ? BPF2SOCKS_UDP_DOWNLINK_SEND_COMPLETE
            : bpf2socks_udp_downlink_classify_send_result(-1, 1U, send_errno);
    }

    struct mmsghdr vec;
    struct iovec iov;
    char control[CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];
    memset(&vec, 0, sizeof(vec));
    memset(control, 0, sizeof(control));
    iov.iov_base = (void *)packet->payload;
    iov.iov_len = packet->payload_len;
    vec.msg_hdr.msg_name = (void *)&session->client_addr;
    vec.msg_hdr.msg_namelen = session->client_addr_len;
    vec.msg_hdr.msg_iov = &iov;
    vec.msg_hdr.msg_iovlen = 1U;
    if (channel->use_pktinfo &&
        fill_udp_downlink_pktinfo(
            &vec.msg_hdr,
            control,
            sizeof(control),
            session,
            packet->binding) < 0) {
        return BPF2SOCKS_UDP_DOWNLINK_SEND_FATAL;
    }
    int sent = sendmmsg(channel->fd, &vec, 1U, 0);
    int send_errno = errno;
    return bpf2socks_udp_downlink_classify_send_result(sent, 1U, send_errno);
}

int bpf2socks_udp_downlink_flush_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_downlink_channel *channel) {
    if (state == NULL || worker == NULL || channel == NULL || channel->ref.session == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_client_session *session = channel->ref.session;
    while (channel->queue.head != NULL) {
        struct bpf2socks_udp_downlink_packet *packet = (struct bpf2socks_udp_downlink_packet *)channel->queue.head;
        enum bpf2socks_udp_downlink_send_result result =
            send_downlink_channel_packet(channel, session, packet);
        if (result == BPF2SOCKS_UDP_DOWNLINK_SEND_RETRY) return 0;
        if (result == BPF2SOCKS_UDP_DOWNLINK_SEND_FATAL) return -1;

        uint64_t now_ms = bpf2socks_now_ms();
        session->last_seen_ms = now_ms;
        packet->binding->last_seen_ms = now_ms;
        ++worker->udp_stats.udp_packets_to_client;
        ++worker->udp_stats.udp_copy_sends;
        (void)bpf2socks_udp_downlink_queue_pop(&channel->queue);
        release_downlink_packet(state, session, packet);
    }
    retire_downlink_channel(state, session, channel, true);
    return 0;
}

int bpf2socks_udp_downlink_batch_flush(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_downlink_batch *batch,
    struct bpf2socks_bridge_worker *worker) {
    if (batch->count == 0U) return 0;

    struct mmsghdr vec[BPF2SOCKS_UDP_MAX_BATCH];
    struct iovec iov[BPF2SOCKS_UDP_MAX_BATCH];
    char control[BPF2SOCKS_UDP_MAX_BATCH][CMSG_SPACE(sizeof(struct in_pktinfo)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];
    memset(vec, 0, sizeof(vec));
    memset(control, 0, sizeof(control));

    for (unsigned int i = 0U; i < batch->count; ++i) {
        const struct bpf2socks_udp_msg *message = batch->messages[i];
        iov[i].iov_base = message->payload;
        iov[i].iov_len = message->payload_len;
        vec[i].msg_hdr.msg_name = &batch->session->client_addr;
        vec[i].msg_hdr.msg_namelen = batch->session->client_addr_len;
        vec[i].msg_hdr.msg_iov = &iov[i];
        vec[i].msg_hdr.msg_iovlen = 1U;
        if (batch->use_pktinfo &&
            fill_udp_downlink_pktinfo(
                &vec[i].msg_hdr,
                control[i],
                sizeof(control[i]),
                batch->session,
                batch->bindings[i]) < 0) {
            return -1;
        }
    }

    int sent = sendmmsg(batch->fd, vec, batch->count, 0);
    int send_errno = errno;
    enum bpf2socks_udp_downlink_send_result result =
        bpf2socks_udp_downlink_classify_send_result(sent, batch->count, send_errno);
    if (result == BPF2SOCKS_UDP_DOWNLINK_SEND_FATAL) {
        errno = send_errno;
        return -1;
    }

    uint64_t now_ms = bpf2socks_now_ms();
    batch->session->last_seen_ms = now_ms;
    int accepted = sent > 0 ? sent : 0;
    for (int i = 0; i < accepted; ++i) {
        batch->bindings[i]->last_seen_ms = now_ms;
        ++worker->udp_stats.udp_packets_to_client;
        ++worker->udp_stats.udp_copy_sends;
    }
    if (result == BPF2SOCKS_UDP_DOWNLINK_SEND_RETRY) {
        if (state == NULL || batch->session->udp_fd < 0) {
            errno = send_errno;
            return -1;
        }
        for (unsigned int i = (unsigned int)accepted; i < batch->count; ++i) {
            if (bpf2socks_udp_downlink_queue_packet(
                    state,
                    batch->session,
                    batch->bindings[i],
                    batch->messages[i],
                    batch->fd,
                    batch->use_pktinfo,
                    false) < 0) {
                return -1;
            }
        }
    }

    bpf2socks_udp_downlink_batch_init(batch);
    return 0;
}

static bool udp_downlink_batch_matches(
    const struct bpf2socks_udp_downlink_batch *batch,
    int fd,
    bool use_pktinfo,
    const struct bpf2socks_udp_client_session *session) {
    return batch->count > 0U &&
        batch->fd == fd &&
        batch->use_pktinfo == use_pktinfo &&
        batch->session == session;
}

int bpf2socks_udp_downlink_batch_queue(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_downlink_batch *batch,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_msg *message,
    int fd,
    bool use_pktinfo) {
    if (bpf2socks_udp_downlink_find_channel(session, binding, fd, use_pktinfo, false) != NULL) {
        if (batch->count > 0U && bpf2socks_udp_downlink_batch_flush(state, batch, worker) < 0) return -1;
        return bpf2socks_udp_downlink_queue_packet(state, session, binding, message, fd, use_pktinfo, false);
    }
    if (batch->count > 0U && !udp_downlink_batch_matches(batch, fd, use_pktinfo, session)) {
        if (bpf2socks_udp_downlink_batch_flush(state, batch, worker) < 0) return -1;
    }
    if (batch->count == 0U) {
        batch->fd = fd;
        batch->use_pktinfo = use_pktinfo;
        batch->session = session;
    }
    batch->bindings[batch->count] = binding;
    batch->messages[batch->count] = message;
    ++batch->count;
    if (batch->count >= BPF2SOCKS_UDP_MAX_BATCH) {
        return bpf2socks_udp_downlink_batch_flush(state, batch, worker);
    }
    return 0;
}
