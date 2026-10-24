// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/udp_binding_index.h"
#include "bridge/udp_budget.h"
#include "bridge/udp_internal.h"
#include "bridge/udp_relay_registry.h"
#include "core/compat.h"
#include "core/log.h"
#include "core/socket_util.h"
#include "core/token.h"
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

/* UDP client sessions and their reply bindings: tables, LRUs, epoll registration. */

bool bpf2socks_udp_control_fd_is_healthy(int fd) {
    uint8_t byte = 0U;
    ssize_t received = recv(fd, &byte, sizeof(byte), MSG_PEEK | MSG_DONTWAIT);
    if (received == 0) return false;
    if (received > 0) return false;
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
}

bool bpf2socks_udp_control_event_is_failure(int fd, uint32_t events) {
    if ((events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0U) return true;
    return (events & EPOLLIN) != 0U && !bpf2socks_udp_control_fd_is_healthy(fd);
}

static bool same_sockaddr(
    const struct sockaddr_storage *a,
    socklen_t a_len,
    const struct sockaddr_storage *b,
    socklen_t b_len) {
    if (a->ss_family != b->ss_family || a_len != b_len) return false;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
        const struct sockaddr_in *ib = (const struct sockaddr_in *)b;
        return ia->sin_port == ib->sin_port && ia->sin_addr.s_addr == ib->sin_addr.s_addr;
    }
    return memcmp(a, b, a_len) == 0;
}

static uint32_t sockaddr_hash(const struct sockaddr_storage *addr, socklen_t addr_len) {
    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        struct {
            uint16_t family;
            uint16_t port;
            uint32_t address;
        } key;
        key.family = AF_INET;
        key.port = in->sin_port;
        key.address = in->sin_addr.s_addr;
        return bpf2socks_hash_bytes(&key, sizeof(key));
    }
    return bpf2socks_hash_bytes(addr, addr_len);
}

bool bpf2socks_udp_packet_needs_original_reply_socket(const struct bpf2socks_udp_client_packet *packet) {
    if (packet == NULL) return false;
    if (packet->connected_udp_token) return false;
    /*
     * A client-less token comes from the cgroup sendmsg hook of a local socket,
     * whose recvmsg hook restores the original peer on replies the listener
     * sends from the token address, so no per-destination socket is needed.
     * TC hotspot tokens have no such hook on the client.
     */
    if (packet->token_lookup_mode == BPF2SOCKS_TOKEN_LOOKUP_ZERO_CLIENT) return false;
    // UDP sockets that kept the original peer need replies sourced from that original destination.
    return packet->original_dst.family == AF_INET || packet->original_dst.family == AF_INET6;
}

bool bpf2socks_udp_packet_uses_connected_token(const struct bpf2socks_udp_client_packet *packet) {
    return packet != NULL && packet->connected_udp_token;
}

static void lru_remove(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (session->lru_prev != NULL) session->lru_prev->lru_next = session->lru_next;
    if (session->lru_next != NULL) session->lru_next->lru_prev = session->lru_prev;
    if (state->lru_head == session) state->lru_head = session->lru_next;
    if (state->lru_tail == session) state->lru_tail = session->lru_prev;
    session->lru_prev = NULL;
    session->lru_next = NULL;
}

static void lru_add_tail(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    session->lru_prev = state->lru_tail;
    session->lru_next = NULL;
    if (state->lru_tail != NULL) state->lru_tail->lru_next = session;
    state->lru_tail = session;
    if (state->lru_head == NULL) state->lru_head = session;
}

void bpf2socks_udp_lru_touch(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (state->lru_tail == session) return;
    lru_remove(state, session);
    lru_add_tail(state, session);
}

/* Sessions enter the handshake list in creation order, so its head expires first. */
void bpf2socks_udp_handshake_add_tail(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint64_t now_ms) {
    session->handshake_started_ms = now_ms;
    session->handshake_prev = state->handshake_tail;
    session->handshake_next = NULL;
    if (state->handshake_tail != NULL) state->handshake_tail->handshake_next = session;
    state->handshake_tail = session;
    if (state->handshake_head == NULL) state->handshake_head = session;
    session->handshake_linked = true;
}

void bpf2socks_udp_handshake_remove(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (!session->handshake_linked) return;
    if (session->handshake_prev != NULL) session->handshake_prev->handshake_next = session->handshake_next;
    if (session->handshake_next != NULL) session->handshake_next->handshake_prev = session->handshake_prev;
    if (state->handshake_head == session) state->handshake_head = session->handshake_next;
    if (state->handshake_tail == session) state->handshake_tail = session->handshake_prev;
    session->handshake_prev = NULL;
    session->handshake_next = NULL;
    session->handshake_linked = false;
}

static void binding_session_lru_remove(
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding) {
    if (session == NULL || binding == NULL) return;
    if (binding->lru_prev != NULL) binding->lru_prev->lru_next = binding->lru_next;
    if (binding->lru_next != NULL) binding->lru_next->lru_prev = binding->lru_prev;
    if (session->binding_lru_head == binding) session->binding_lru_head = binding->lru_next;
    if (session->binding_lru_tail == binding) session->binding_lru_tail = binding->lru_prev;
    binding->lru_prev = NULL;
    binding->lru_next = NULL;
}

static void binding_session_lru_add_tail(
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding) {
    binding->lru_prev = session->binding_lru_tail;
    binding->lru_next = NULL;
    if (session->binding_lru_tail != NULL) session->binding_lru_tail->lru_next = binding;
    session->binding_lru_tail = binding;
    if (session->binding_lru_head == NULL) session->binding_lru_head = binding;
}

static void binding_global_lru_remove(struct bpf2socks_udp_state *state, struct bpf2socks_udp_reply_binding *binding) {
    if (state == NULL || binding == NULL) return;
    if (binding->global_lru_prev != NULL) binding->global_lru_prev->global_lru_next = binding->global_lru_next;
    if (binding->global_lru_next != NULL) binding->global_lru_next->global_lru_prev = binding->global_lru_prev;
    if (state->binding_lru_head == binding) state->binding_lru_head = binding->global_lru_next;
    if (state->binding_lru_tail == binding) state->binding_lru_tail = binding->global_lru_prev;
    binding->global_lru_prev = NULL;
    binding->global_lru_next = NULL;
}

static void binding_global_lru_add_tail(struct bpf2socks_udp_state *state, struct bpf2socks_udp_reply_binding *binding) {
    binding->global_lru_prev = state->binding_lru_tail;
    binding->global_lru_next = NULL;
    if (state->binding_lru_tail != NULL) state->binding_lru_tail->global_lru_next = binding;
    state->binding_lru_tail = binding;
    if (state->binding_lru_head == NULL) state->binding_lru_head = binding;
}

void bpf2socks_udp_binding_lru_touch(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding) {
    if (state == NULL || session == NULL || binding == NULL) return;
    if (session->binding_lru_tail != binding) {
        binding_session_lru_remove(session, binding);
        binding_session_lru_add_tail(session, binding);
    }
    if (state->binding_lru_tail != binding) {
        binding_global_lru_remove(state, binding);
        binding_global_lru_add_tail(state, binding);
    }
}

static struct bpf2socks_udp_reply_binding *alloc_binding(struct bpf2socks_udp_state *state) {
    if (state == NULL || state->free_bindings == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    struct bpf2socks_udp_reply_binding *binding = state->free_bindings;
    state->free_bindings = binding->free_next;
    memset(binding, 0, sizeof(*binding));
    binding->reply_fd = -1;
    return binding;
}

void bpf2socks_udp_binding_close_reply(struct bpf2socks_udp_reply_binding *binding) {
    if (binding == NULL) return;
    if (binding->reply_fd >= 0) close(binding->reply_fd);
    binding->reply_fd = -1;
    binding->reply_raw = false;
    ++binding->reply_fd_generation;
}

void bpf2socks_udp_binding_set_reply(
    struct bpf2socks_udp_reply_binding *binding,
    int fd,
    bool reply_raw) {
    if (binding == NULL) return;
    binding->reply_fd = fd;
    binding->reply_raw = reply_raw;
    ++binding->reply_fd_generation;
}

static void release_binding(struct bpf2socks_udp_state *state, struct bpf2socks_udp_reply_binding *binding) {
    if (state == NULL || binding == NULL) return;
    bpf2socks_udp_binding_close_reply(binding);
    memset(binding, 0, sizeof(*binding));
    binding->reply_fd = -1;
    binding->free_next = state->free_bindings;
    state->free_bindings = binding;
}

static void unlink_binding_from_session(
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding) {
    struct bpf2socks_udp_reply_binding **slot = &session->bindings;
    while (*slot != NULL) {
        if (*slot == binding) {
            *slot = binding->next;
            binding->next = NULL;
            return;
        }
        slot = &(*slot)->next;
    }
}

static void destroy_binding(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding) {
    if (session == NULL || binding == NULL) return;
    (void)bpf2socks_udp_binding_index_remove(&state->binding_index, binding);
    unlink_binding_from_session(session, binding);
    binding_session_lru_remove(session, binding);
    binding_global_lru_remove(state, binding);
    if (session->binding_count > 0U) --session->binding_count;
    if (state != NULL && state->binding_count > 0U) --state->binding_count;
    release_binding(state, binding);
}

static int evict_binding(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_bridge_worker *worker) {
    struct bpf2socks_udp_reply_binding *binding = NULL;
    if (session != NULL) {
        for (binding = session->binding_lru_head;
            binding != NULL && binding->downlink_pending_count > 0U;
            binding = binding->lru_next) {
        }
    } else if (state != NULL) {
        for (binding = state->binding_lru_head;
            binding != NULL && binding->downlink_pending_count > 0U;
            binding = binding->global_lru_next) {
        }
        if (binding != NULL) session = binding->owner;
    }
    if (binding == NULL || session == NULL) {
        errno = ENOMEM;
        return -1;
    }
    destroy_binding(state, session, binding);
    ++worker->udp_stats.udp_binding_evictions;
    return 0;
}

static int ensure_binding_capacity(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker) {
    while (state->binding_count >= state->binding_cap) {
        if (evict_binding(state, NULL, worker) < 0) return -1;
    }
    return 0;
}

size_t bpf2socks_udp_session_index(const struct bpf2socks_udp_state *state, const struct bpf2socks_udp_client_session *session) {
    return (size_t)(session - state->sessions);
}

int bpf2socks_udp_epoll_add_events(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref, uint32_t events) {
    if (state->epoll_fd < 0 || fd < 0 || ref == NULL) return 0;
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events | EPOLLERR | EPOLLHUP;
    event.data.ptr = ref;
    return epoll_ctl(state->epoll_fd, EPOLL_CTL_ADD, fd, &event);
}

int bpf2socks_udp_epoll_modify(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref, uint32_t events) {
    if (state->epoll_fd < 0 || fd < 0 || ref == NULL) return 0;
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events | EPOLLERR | EPOLLHUP;
    event.data.ptr = ref;
    return epoll_ctl(state->epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

int bpf2socks_udp_epoll_add(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref) {
    return bpf2socks_udp_epoll_add_events(state, fd, ref, EPOLLIN);
}

void bpf2socks_udp_epoll_remove(struct bpf2socks_udp_state *state, int fd) {
    if (state == NULL || state->epoll_fd < 0 || fd < 0) return;
    (void)epoll_ctl(state->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

static int add_session_udp_epoll_fd(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    size_t index = bpf2socks_udp_session_index(state, session);
    if (index >= state->session_cap) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_fd_ref *ref = &state->session_refs[index].relay;
    ref->kind = BPF2SOCKS_UDP_FD_SESSION_RELAY;
    ref->fd = session->udp_fd;
    ref->session = session;
    return bpf2socks_udp_epoll_add(state, session->udp_fd, ref);
}

int bpf2socks_udp_epoll_add_session_control(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session, uint32_t events) {
    size_t index = bpf2socks_udp_session_index(state, session);
    if (index >= state->session_cap) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_fd_ref *ref = &state->session_refs[index].control;
    ref->kind = BPF2SOCKS_UDP_FD_SESSION_CONTROL;
    ref->fd = session->tcp_fd;
    ref->session = session;
    return bpf2socks_udp_epoll_add_events(state, session->tcp_fd, ref, events);
}

int bpf2socks_udp_epoll_switch_session_to_relay(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    size_t index = bpf2socks_udp_session_index(state, session);
    if (index >= state->session_cap) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_fd_ref *control_ref = &state->session_refs[index].control;
    if (bpf2socks_udp_epoll_modify(
            state,
            session->tcp_fd,
            control_ref,
            EPOLLIN | EPOLLRDHUP) < 0) {
        return -1;
    }
    return add_session_udp_epoll_fd(state, session);
}

static struct bpf2socks_udp_pending_packet *alloc_pending_packet(
    struct bpf2socks_udp_state *state,
    size_t payload_len) {
    if (state == NULL || state->pending_budget == NULL ||
        payload_len > SIZE_MAX - sizeof(struct bpf2socks_udp_pending_packet)) {
        errno = ENOBUFS;
        return NULL;
    }
    size_t allocation_bytes = sizeof(struct bpf2socks_udp_pending_packet) + payload_len;
    if (bpf2socks_udp_budget_reserve(state->pending_budget, allocation_bytes) < 0) return NULL;
    struct bpf2socks_udp_pending_packet *packet = malloc(allocation_bytes);
    if (packet == NULL) {
        (void)bpf2socks_udp_budget_release(state->pending_budget, allocation_bytes);
        errno = ENOMEM;
        return NULL;
    }
    memset(packet, 0, sizeof(*packet));
    packet->payload = (uint8_t *)(packet + 1);
    packet->allocation_bytes = allocation_bytes;
    return packet;
}

void bpf2socks_udp_session_release_pending(struct bpf2socks_udp_state *state, struct bpf2socks_udp_pending_packet *packet) {
    if (state == NULL || packet == NULL) return;
    size_t allocation_bytes = packet->allocation_bytes;
    free(packet);
    if (state->pending_budget != NULL) {
        (void)bpf2socks_udp_budget_release(state->pending_budget, allocation_bytes);
    }
}

static void release_session_pending_packets(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (state == NULL || session == NULL) return;
    struct bpf2socks_udp_pending_packet *packet = session->pending_head;
    while (packet != NULL) {
        struct bpf2socks_udp_pending_packet *next = packet->next;
        bpf2socks_udp_session_release_pending(state, packet);
        packet = next;
    }
    session->pending_head = NULL;
    session->pending_tail = NULL;
    session->pending_count = 0U;
}

int bpf2socks_udp_session_queue_pending(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *original_dst,
    const uint8_t *payload,
    size_t payload_len,
    size_t payload_cap) {
    if (state == NULL || session == NULL || original_dst == NULL || payload == NULL || payload_len > payload_cap) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_udp_pending_packet *packet = alloc_pending_packet(state, payload_len);
    if (packet == NULL) return -1;
    packet->original_dst = *original_dst;
    packet->payload_len = payload_len;
    memcpy(packet->payload, payload, payload_len);
    packet->next = NULL;
    if (session->pending_tail != NULL) {
        session->pending_tail->next = packet;
    } else {
        session->pending_head = packet;
    }
    session->pending_tail = packet;
    ++session->pending_count;
    session->last_seen_ms = bpf2socks_now_ms();
    bpf2socks_udp_lru_touch(state, session);
    return 0;
}

void bpf2socks_udp_session_close(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (session == NULL || !session->used) return;
    if (session->relay_port_claimed) {
        bpf2socks_udp_relay_port_release(state->relay_registry, session->relay_port);
    }
    release_session_pending_packets(state, session);
    bpf2socks_udp_downlink_release_session(state, session);
    if (session->tcp_fd >= 0) close(session->tcp_fd);
    if (session->udp_fd >= 0) close(session->udp_fd);
    while (session->bindings != NULL) {
        destroy_binding(state, session, session->bindings);
    }
    memset(session, 0, sizeof(*session));
    session->tcp_fd = -1;
    session->udp_fd = -1;
}

static uint32_t session_bucket(const struct sockaddr_storage *addr, socklen_t addr_len) {
    return sockaddr_hash(addr, addr_len) % BPF2SOCKS_SESSION_HASH_BUCKETS;
}

struct bpf2socks_udp_client_session *bpf2socks_udp_session_find(
    struct bpf2socks_udp_state *state,
    const struct sockaddr_storage *client_addr,
    socklen_t client_addr_len) {
    uint32_t bucket = session_bucket(client_addr, client_addr_len);
    for (struct bpf2socks_udp_client_session *session = state->session_buckets[bucket];
         session != NULL;
         session = session->next) {
        if (session->used &&
            same_sockaddr(&session->client_addr, session->client_addr_len, client_addr, client_addr_len)) {
            return session;
        }
    }
    return NULL;
}

static void unlink_session_from_hash(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    uint32_t bucket = session_bucket(&session->client_addr, session->client_addr_len);
    struct bpf2socks_udp_client_session **slot = &state->session_buckets[bucket];
    while (*slot != NULL) {
        if (*slot == session) {
            *slot = session->next;
            session->next = NULL;
            return;
        }
        slot = &(*slot)->next;
    }
}

void bpf2socks_udp_session_drop(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session) {
    if (state == NULL || session == NULL || !session->used) return;
    bpf2socks_udp_epoll_remove(state, session->tcp_fd);
    bpf2socks_udp_epoll_remove(state, session->udp_fd);
    size_t index = bpf2socks_udp_session_index(state, session);
    if (index < state->session_cap) {
        memset(&state->session_refs[index], 0, sizeof(state->session_refs[index]));
        state->session_refs[index].control.kind = BPF2SOCKS_UDP_FD_SESSION_CONTROL;
        state->session_refs[index].control.fd = -1;
        state->session_refs[index].relay.kind = BPF2SOCKS_UDP_FD_SESSION_RELAY;
        state->session_refs[index].relay.fd = -1;
    }
    unlink_session_from_hash(state, session);
    lru_remove(state, session);
    bpf2socks_udp_handshake_remove(state, session);
    if (bpf2socks_sockaddr_is_loopback(&session->client_addr) && state->local_session_count > 0U) {
        --state->local_session_count;
    }
    bpf2socks_udp_session_close(state, session);
    if (state->session_count > 0U) --state->session_count;
    session->free_next = state->free_sessions;
    state->free_sessions = session;
}

void bpf2socks_udp_session_control_event(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint32_t events) {
    if (session == NULL || session->tcp_fd < 0) return;
    if (bpf2socks_udp_control_event_is_failure(session->tcp_fd, events)) {
        bpf2socks_udp_session_drop(state, session);
    }
}

static struct bpf2socks_udp_client_session *alloc_session(struct bpf2socks_udp_state *state, struct bpf2socks_bridge_worker *worker) {
    if (state->free_sessions != NULL) {
        struct bpf2socks_udp_client_session *session = state->free_sessions;
        state->free_sessions = session->free_next;
        session->free_next = NULL;
        return session;
    }
    /*
     * Sessions that already exchanged datagrams move to the LRU tail, so the
     * least recently seen ones are often still in the SOCKS5 handshake with
     * their first datagram queued. Evict an established session first and a
     * handshaking one only when nothing else can go.
     */
    struct bpf2socks_udp_client_session *victim = NULL;
    for (int pass = 0; pass < 2 && victim == NULL; ++pass) {
        for (struct bpf2socks_udp_client_session *candidate = state->lru_head;
             candidate != NULL;
             candidate = candidate->lru_next) {
            if (candidate->downlink_pending_count > 0U || candidate->downlink_waiting_budget) continue;
            if (pass == 0 && candidate->stage != BPF2SOCKS_UDP_SESSION_READY) continue;
            victim = candidate;
            break;
        }
    }
    if (victim == NULL) {
        errno = ENOBUFS;
        return NULL;
    }
    bpf2socks_udp_session_drop(state, victim);
    ++worker->udp_stats.udp_session_evictions;
    return alloc_session(state, worker);
}

struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_find(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *original,
    struct bpf2socks_bridge_worker *worker) {
    if (state == NULL || session == NULL || original == NULL) return NULL;
    uint64_t collision_steps = 0U;
    struct bpf2socks_udp_reply_binding *binding = bpf2socks_udp_binding_index_find(
        &state->binding_index,
        session,
        original,
        &collision_steps);
    if (worker != NULL) {
        ++worker->udp_stats.udp_binding_hash_lookups;
        worker->udp_stats.udp_binding_hash_collision_steps += collision_steps;
    }
    return binding;
}

static struct bpf2socks_udp_reply_binding *create_binding(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *original,
    const uint8_t *token_addr,
    size_t token_addr_len,
    bool connected_udp_token,
    bool needs_original_reply_socket,
    bool fullcone,
    struct bpf2socks_bridge_worker *worker) {
    if (ensure_binding_capacity(state, worker) < 0) return NULL;
    struct bpf2socks_udp_reply_binding *binding = alloc_binding(state);
    if (binding == NULL) return NULL;
    binding->original_dst = *original;
    if (token_addr != NULL && token_addr_len > 0U) {
        if (token_addr_len > sizeof(binding->token_addr)) token_addr_len = sizeof(binding->token_addr);
        memcpy(binding->token_addr, token_addr, token_addr_len);
    }
    binding->last_seen_ms = bpf2socks_now_ms();
    binding->connected_udp_token = connected_udp_token;
    if (needs_original_reply_socket) {
        bool reply_raw = false;
        int reply_fd = bpf2socks_udp_reply_socket_create(original, &reply_raw);
        if (reply_fd < 0) {
            BPF2SOCKS_LOG_THROTTLED("failed to create UDP original reply socket: errno=%d", errno);
            release_binding(state, binding);
            return NULL;
        }
        bpf2socks_udp_binding_set_reply(binding, reply_fd, reply_raw);
    }
    binding->used = true;
    binding->owner = session;
    if (bpf2socks_udp_binding_index_insert(&state->binding_index, binding) != 0) {
        release_binding(state, binding);
        return NULL;
    }
    binding->next = session->bindings;
    session->bindings = binding;
    binding_session_lru_add_tail(session, binding);
    binding_global_lru_add_tail(state, binding);
    ++session->binding_count;
    ++state->binding_count;
    ++worker->udp_stats.udp_reply_binding_creates;
    if (fullcone) ++worker->udp_stats.udp_fullcone_binding_creates;
    return binding;
}

struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_create_for_packet(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_client_packet *packet,
    struct bpf2socks_bridge_worker *worker) {
    return create_binding(
        state,
        session,
        &packet->original_dst,
        packet->token_addr,
        packet->token_family == AF_INET6 ? 16U : 4U,
        packet->connected_udp_token,
        !bpf2socks_udp_packet_uses_connected_token(packet) &&
            (packet->original_from_socket || bpf2socks_udp_packet_needs_original_reply_socket(packet)),
        false,
        worker);
}

struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_create_fullcone(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *remote,
    struct bpf2socks_bridge_worker *worker) {
    return create_binding(
        state,
        session,
        remote,
        NULL,
        0U,
        false,
        remote->family == AF_INET || remote->family == AF_INET6,
        true,
        worker);
}

bool bpf2socks_udp_binding_has_token(const struct bpf2socks_udp_reply_binding *binding) {
    static const uint8_t no_token[16];
    return memcmp(binding->token_addr, no_token, sizeof(no_token)) != 0;
}

/*
 * A reply addressed by domain (SOCKS5 ATYP 3) answers a datagram the client
 * sent to an address the server mapped to that domain, such as a FakeIP.
 * Take the most recently used client-created binding with the same port.
 */
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_find_by_domain_port(
    struct bpf2socks_udp_client_session *session,
    uint16_t port) {
    struct bpf2socks_udp_reply_binding *best = NULL;
    for (struct bpf2socks_udp_reply_binding *binding = session->bindings;
         binding != NULL;
         binding = binding->next) {
        if (!binding->used || binding->original_dst.port != port || !bpf2socks_udp_binding_has_token(binding)) {
            continue;
        }
        if (best == NULL || binding->last_seen_ms > best->last_seen_ms) best = binding;
    }
    return best;
}

struct bpf2socks_udp_client_session *bpf2socks_udp_session_get(
    struct bpf2socks_udp_state *state,
    const struct bpf2socks_udp_client_packet *packet,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session) {
    if (session != NULL) {
        session->last_seen_ms = bpf2socks_now_ms();
        bpf2socks_udp_lru_touch(state, session);
        if (packet->token_lookup_mode != BPF2SOCKS_TOKEN_LOOKUP_UNKNOWN) {
            session->token_lookup_mode = packet->token_lookup_mode;
        }
        ++worker->udp_stats.udp_session_hits;
        ++worker->udp_stats.udp_associate_reuses;
        return session;
    }

    ++worker->udp_stats.udp_session_misses;
    bool local = bpf2socks_sockaddr_is_loopback(&packet->client_addr);
    /* Catch up on closes queued while unwatched before this session can match one. */
    if (local && !state->destroy_events_armed) bpf2socks_udp_release_arm(state, worker, bpf2socks_now_ms());
    session = alloc_session(state, worker);
    if (session == NULL) return NULL;
    memset(session, 0, sizeof(*session));
    session->tcp_fd = -1;
    session->udp_fd = -1;
    session->used = true;
    session->client_addr = packet->client_addr;
    session->client_addr_len = packet->client_addr_len;
    session->token_lookup_mode = packet->token_lookup_mode;
    session->last_seen_ms = bpf2socks_now_ms();
    if (bpf2socks_udp_associate_build_request(session) < 0) {
        bpf2socks_udp_session_close(state, session);
        session->free_next = state->free_sessions;
        state->free_sessions = session;
        return NULL;
    }
    session->tcp_fd = bpf2socks_udp_associate_open(
        (const struct sockaddr *)&worker->socks_addr,
        worker->socks_addr_len,
        &session->stage);
    if (session->tcp_fd < 0) {
        bpf2socks_udp_session_close(state, session);
        session->free_next = state->free_sessions;
        state->free_sessions = session;
        return NULL;
    }
    uint32_t bucket = session_bucket(&session->client_addr, session->client_addr_len);
    session->next = state->session_buckets[bucket];
    state->session_buckets[bucket] = session;
    lru_add_tail(state, session);
    bpf2socks_udp_handshake_add_tail(state, session, session->last_seen_ms);
    ++state->session_count;
    if (local) ++state->local_session_count;
    if (bpf2socks_udp_epoll_add_session_control(state, session, EPOLLIN | EPOLLOUT) < 0) {
        bpf2socks_udp_session_drop(state, session);
        return NULL;
    }
    bpf2socks_udp_release_note_new_session(state, session, session->last_seen_ms);
    return session;
}

/*
 * A SOCKS5 server that never answers the UDP ASSOCIATE handshake would
 * otherwise hold the session, and every datagram the client sends to it,
 * until the idle timeout. The connect timeout bounds the handshake, so
 * the client's next datagram opens a fresh association.
 */
void bpf2socks_udp_session_expire_handshakes(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms) {
    uint64_t timeout_ms = worker->config->connect_timeout_milliseconds;
    while (state->handshake_head != NULL && now_ms != 0U &&
           now_ms - state->handshake_head->handshake_started_ms >= timeout_ms) {
        ++worker->udp_stats.udp_associate_timeouts;
        bpf2socks_udp_session_drop(state, state->handshake_head);
    }
}

void bpf2socks_udp_session_expire_idle(struct bpf2socks_udp_state *state) {
    uint64_t now_ms = bpf2socks_now_ms();
    if (now_ms == 0U) return;
    uint64_t timeout_ms = state->idle_timeout_ms;
    struct bpf2socks_udp_client_session *session = state->lru_head;
    while (session != NULL) {
        struct bpf2socks_udp_client_session *next = session->lru_next;
        if (!session->used || now_ms - session->last_seen_ms < timeout_ms) {
            break;
        }
        if (session->downlink_pending_count > 0U || session->downlink_waiting_budget) {
            session = next;
            continue;
        }
        bpf2socks_udp_session_drop(state, session);
        session = next;
    }
}

void bpf2socks_udp_binding_expire_idle(struct bpf2socks_udp_state *state, struct bpf2socks_bridge_worker *worker) {
    uint64_t now_ms = bpf2socks_now_ms();
    if (now_ms == 0U) return;
    uint64_t timeout_ms = state->idle_timeout_ms;
    struct bpf2socks_udp_reply_binding *binding = state->binding_lru_head;
    while (binding != NULL) {
        struct bpf2socks_udp_reply_binding *next = binding->global_lru_next;
        if (!binding->used || now_ms - binding->last_seen_ms < timeout_ms) break;
        if (binding->downlink_pending_count > 0U) {
            binding = next;
            continue;
        }
        struct bpf2socks_udp_client_session *session = binding->owner;
        destroy_binding(state, session, binding);
        ++worker->udp_stats.udp_binding_evictions;
        binding = next;
    }
}
