// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#define _GNU_SOURCE

#include "bpf2socks.h"
#include "bridge/internal.h"
#include "bridge/socks5.h"
#include "bridge/stats.h"
#include "core/compat.h"
#include "core/log.h"
#include "core/original_dst.h"
#include "core/socket_util.h"
#include "core/stop_event.h"
#include "core/token.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define BPF2SOCKS_TCP_EVENTS 256
#define BPF2SOCKS_TCP_HANDSHAKE_CAP 32U
/* Method reply (2) plus the largest CONNECT reply (4 + 1 + 255 + 2). */
#define BPF2SOCKS_TCP_RESPONSE_CAP 264U
#define BPF2SOCKS_TCP_SPLICE_CHUNK 65536U
/* Requested relay pipe capacity; the kernel keeps the default when refused. */
#define BPF2SOCKS_TCP_PIPE_SIZE 262144
#define BPF2SOCKS_TCP_RELAY_EVENTS (EPOLLERR | EPOLLHUP | EPOLLRDHUP)
/*
 * Before the relay starts, a client half-close is not fatal: its data and FIN
 * stay queued until splicing begins, so only errors and full hangups matter.
 */
#define BPF2SOCKS_TCP_HANDSHAKE_CLIENT_EVENTS (EPOLLERR | EPOLLHUP)
#define BPF2SOCKS_TCP_STATS_PUBLISH_MILLISECONDS 250U

enum tcp_stage {
    TCP_STAGE_CONNECTING,
    /* The method hello and the CONNECT request are written together. */
    TCP_STAGE_REQUEST_WRITE,
    TCP_STAGE_REPLY_READ,
    TCP_STAGE_RELAY,
};

enum tcp_side {
    TCP_SIDE_LISTENER,
    TCP_SIDE_CLIENT,
    TCP_SIDE_UPSTREAM,
};

struct tcp_connection;

/* Empty relay pipes kept per worker so new relays skip pipe2/F_SETPIPE_SZ. */
struct tcp_pipe_pool {
    int read_fds[BPF2SOCKS_TCP_PIPE_POOL_CAP];
    int write_fds[BPF2SOCKS_TCP_PIPE_POOL_CAP];
    size_t capacities[BPF2SOCKS_TCP_PIPE_POOL_CAP];
    size_t count;
};

struct tcp_fd_ref {
    struct tcp_connection *connection;
    enum tcp_side side;
    int fd;
    uint32_t events;
};

struct tcp_splice_pipe {
    int read_fd;
    int write_fd;
    size_t capacity;
    size_t queued;
    bool input_eof;
    bool input_paused;
    bool output_shutdown;
};

struct tcp_connection {
    int client_fd;
    int upstream_fd;
    enum tcp_stage stage;
    bool closing;
    bool session_reserved;
    struct bpf2socks_bridge_worker *worker;
    struct tcp_pipe_pool *pipe_pool;
    struct tcp_fd_ref client_ref;
    struct tcp_fd_ref upstream_ref;
    struct tcp_splice_pipe client_to_upstream;
    struct tcp_splice_pipe upstream_to_client;
    struct bpf2socks_sockaddr target;
    uint8_t handshake[BPF2SOCKS_TCP_HANDSHAKE_CAP];
    size_t handshake_length;
    size_t handshake_offset;
    uint8_t response[BPF2SOCKS_TCP_RESPONSE_CAP];
    size_t response_length;
    size_t response_expected;
    uint64_t created_at_ms;
    uint64_t last_activity_ms;
    bool active_linked;
    struct tcp_connection *active_prev;
    struct tcp_connection *active_next;
    struct tcp_connection *next;
};


struct tcp_worker_state {
    struct bpf2socks_bridge_worker *worker;
    struct tcp_fd_ref listener4_ref;
    struct tcp_fd_ref listener6_ref;
    struct tcp_connection *active;
    struct tcp_connection *closed;
    struct tcp_pipe_pool pipe_pool;
    /* Earliest connect/idle deadline; activity only moves deadlines later. */
    uint64_t next_deadline_ms;
    uint64_t next_stats_publish_ms;
    uint64_t listeners_resume_ms;
    int spare_fd;
    bool listeners_paused;
};

static void release_tcp_session(struct tcp_connection *connection);

static void connection_touch(struct tcp_connection *connection) {
    if (connection == NULL) return;
    uint64_t now_ms = bpf2socks_now_ms();
    if (now_ms != 0U) connection->last_activity_ms = now_ms;
}

static int fill_tcp_token_key(
    int client_fd,
    const struct sockaddr_storage *peer,
    struct bpf2socks_token_key *key) {
    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(client_fd, (struct sockaddr *)&local, &local_len) != 0) return -1;
    memset(key, 0, sizeof(*key));
    key->protocol = BPF2SOCKS_PROTO_TCP;

    if (local.ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)&local;
        key->family = AF_INET;
        key->token_port = ntohs(addr->sin_port);
        memcpy(key->token_addr, &addr->sin_addr, 4U);
    } else if (local.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&local;
        key->family = AF_INET6;
        key->token_port = ntohs(addr->sin6_port);
        memcpy(key->token_addr, &addr->sin6_addr, 16U);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *peer_addr = (const struct sockaddr_in *)peer;
        key->client_port = ntohs(peer_addr->sin_port);
        memcpy(key->client_addr, &peer_addr->sin_addr, 4U);
    } else if (peer->ss_family == AF_INET6) {
        const struct sockaddr_in6 *peer_addr = (const struct sockaddr_in6 *)peer;
        key->client_port = ntohs(peer_addr->sin6_port);
        memcpy(key->client_addr, &peer_addr->sin6_addr, 16U);
    }
    return 0;
}

/* Loopback clients try the client-less key first; see bpf2socks_token_key_is_loopback. */
static int lookup_original_with_client_fallback(
    int map_fd,
    const struct bpf2socks_token_key *key,
    struct bpf2socks_original_dst *original,
    struct bpf2socks_bridge_stats *stats) {
    struct bpf2socks_token_key zero_client = *key;
    zero_client.client_port = 0U;
    memset(zero_client.client_addr, 0, sizeof(zero_client.client_addr));
    bool zero_first = bpf2socks_token_key_is_loopback(key);
    const struct bpf2socks_token_key *first = zero_first ? &zero_client : key;
    const struct bpf2socks_token_key *second = zero_first ? key : &zero_client;
    bool delete_failed = false;
    if (bpf2socks_token_take(map_fd, first, original, &delete_failed) < 0 &&
        bpf2socks_token_take(map_fd, second, original, &delete_failed) < 0) {
        return -1;
    }
    if (delete_failed) ++stats->tcp_token_delete_failures;
    return 0;
}

static int lookup_tcp_original_from_socket(
    int client_fd,
    const struct bpf2socks_runtime_config *config,
    struct bpf2socks_original_dst *original) {
    struct sockaddr_storage original_addr;
    socklen_t original_len = sizeof(original_addr);
    memset(&original_addr, 0, sizeof(original_addr));
    if (getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST, &original_addr, &original_len) == 0 &&
        bpf2socks_original_dst_from_sockaddr(
            &original_addr,
            config,
            BPF2SOCKS_PROTO_TCP,
            original) == 0) {
        return 0;
    }

    struct sockaddr_storage original6_addr;
    socklen_t original6_len = sizeof(original6_addr);
    memset(&original6_addr, 0, sizeof(original6_addr));
    if (getsockopt(client_fd, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, &original6_addr, &original6_len) == 0 &&
        bpf2socks_original_dst_from_sockaddr(
            &original6_addr,
            config,
            BPF2SOCKS_PROTO_TCP,
            original) == 0) {
        return 0;
    }

    struct sockaddr_storage local;
    socklen_t local_len = sizeof(local);
    if (getsockname(client_fd, (struct sockaddr *)&local, &local_len) != 0) {
        return -1;
    }
    return bpf2socks_original_dst_from_sockaddr(&local, config, BPF2SOCKS_PROTO_TCP, original);
}

/* Live connections form an intrusive doubly linked list; removal never scans. */
static void active_add(struct tcp_worker_state *state, struct tcp_connection *connection) {
    if (connection->active_linked) return;
    connection->active_prev = NULL;
    connection->active_next = state->active;
    if (state->active != NULL) state->active->active_prev = connection;
    state->active = connection;
    connection->active_linked = true;
}

static void active_remove(struct tcp_worker_state *state, struct tcp_connection *connection) {
    if (!connection->active_linked) return;
    if (connection->active_prev != NULL) {
        connection->active_prev->active_next = connection->active_next;
    } else {
        state->active = connection->active_next;
    }
    if (connection->active_next != NULL) connection->active_next->active_prev = connection->active_prev;
    connection->active_prev = NULL;
    connection->active_next = NULL;
    connection->active_linked = false;
}

static void closed_add(struct tcp_worker_state *state, struct tcp_connection *connection) {
    connection->next = state->closed;
    state->closed = connection;
}

static void init_splice_pipe(struct tcp_splice_pipe *pipe_state) {
    pipe_state->read_fd = -1;
    pipe_state->write_fd = -1;
    pipe_state->capacity = BPF2SOCKS_TCP_SPLICE_CHUNK;
    pipe_state->queued = 0U;
    pipe_state->input_eof = false;
    pipe_state->input_paused = false;
    pipe_state->output_shutdown = false;
}

static int open_splice_pipe(struct tcp_pipe_pool *pool, struct tcp_splice_pipe *pipe_state) {
    init_splice_pipe(pipe_state);
    if (pool != NULL && pool->count > 0U) {
        --pool->count;
        pipe_state->read_fd = pool->read_fds[pool->count];
        pipe_state->write_fd = pool->write_fds[pool->count];
        pipe_state->capacity = pool->capacities[pool->count];
        return 0;
    }
    int fds[2] = {-1, -1};
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) return -1;
    pipe_state->read_fd = fds[0];
    pipe_state->write_fd = fds[1];
#ifdef F_SETPIPE_SZ
    int capacity = fcntl(fds[1], F_SETPIPE_SZ, BPF2SOCKS_TCP_PIPE_SIZE);
    if (capacity > 0) pipe_state->capacity = (size_t)capacity;
#endif
    return 0;
}

static void close_splice_pipe(struct tcp_splice_pipe *pipe_state) {
    bpf2socks_close_fd(&pipe_state->read_fd);
    bpf2socks_close_fd(&pipe_state->write_fd);
    pipe_state->queued = 0U;
    pipe_state->input_eof = true;
    pipe_state->input_paused = false;
    pipe_state->output_shutdown = true;
}

/* Only a pipe known to be empty may be reused; anything else is closed. */
static void release_splice_pipe(struct tcp_pipe_pool *pool, struct tcp_splice_pipe *pipe_state) {
    if (pool != NULL && pipe_state->read_fd >= 0 && pipe_state->write_fd >= 0 &&
        pipe_state->queued == 0U && pool->count < BPF2SOCKS_TCP_PIPE_POOL_CAP) {
        pool->read_fds[pool->count] = pipe_state->read_fd;
        pool->write_fds[pool->count] = pipe_state->write_fd;
        pool->capacities[pool->count] = pipe_state->capacity;
        ++pool->count;
        pipe_state->read_fd = -1;
        pipe_state->write_fd = -1;
    }
    close_splice_pipe(pipe_state);
}

static void close_pipe_pool(struct tcp_pipe_pool *pool) {
    while (pool->count > 0U) {
        --pool->count;
        close(pool->read_fds[pool->count]);
        close(pool->write_fds[pool->count]);
    }
}

static int init_connection_splice_pipes(struct tcp_connection *connection) {
    if (open_splice_pipe(connection->pipe_pool, &connection->client_to_upstream) != 0) return -1;
    if (open_splice_pipe(connection->pipe_pool, &connection->upstream_to_client) != 0) {
        close_splice_pipe(&connection->client_to_upstream);
        return -1;
    }
    return 0;
}

/*
 * Makes the next close() send an RST, so the peer reads a failure
 * (ECONNRESET) instead of an orderly EOF it could mistake for a complete
 * stream or a server that simply closed.
 */
static void reset_on_close(int fd) {
    if (fd < 0) return;
    struct linger linger = {.l_onoff = 1, .l_linger = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
}

static void free_connection(struct tcp_connection *connection) {
    if (connection == NULL) return;
    bpf2socks_close_fd(&connection->client_fd);
    bpf2socks_close_fd(&connection->upstream_fd);
    release_splice_pipe(connection->pipe_pool, &connection->client_to_upstream);
    release_splice_pipe(connection->pipe_pool, &connection->upstream_to_client);
    free(connection);
}

static void free_closed_connections(struct tcp_worker_state *state) {
    struct tcp_connection *connection = state->closed;
    state->closed = NULL;
    /* Closing connections frees descriptors: retry paused listeners right away. */
    if (connection != NULL && state->listeners_paused) state->listeners_resume_ms = 0U;
    while (connection != NULL) {
        struct tcp_connection *next = connection->next;
        free_connection(connection);
        connection = next;
    }
}

static void close_connection(struct tcp_worker_state *state, struct tcp_connection *connection) {
    if (connection == NULL || connection->closing) return;
    connection->closing = true;
    connection->client_ref.connection = NULL;
    connection->upstream_ref.connection = NULL;
    active_remove(state, connection);
    release_tcp_session(connection);
    if (connection->client_fd >= 0) {
        (void)epoll_ctl(state->worker->epoll_fd, EPOLL_CTL_DEL, connection->client_fd, NULL);
        close(connection->client_fd);
        connection->client_fd = -1;
    }
    if (connection->upstream_fd >= 0) {
        (void)epoll_ctl(state->worker->epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        close(connection->upstream_fd);
        connection->upstream_fd = -1;
    }
    closed_add(state, connection);
}

/* One side failed or was reset: close it and reset the other side's peer. */
static void reset_connection(
    struct tcp_worker_state *state,
    struct tcp_connection *connection,
    enum tcp_side failed_side) {
    if (connection == NULL || connection->closing) return;
    reset_on_close(failed_side == TCP_SIDE_CLIENT ? connection->upstream_fd : connection->client_fd);
    close_connection(state, connection);
}

static void close_all_active(struct tcp_worker_state *state) {
    while (state->active != NULL) {
        close_connection(state, state->active);
    }
    free_closed_connections(state);
}

static uint64_t connection_deadline(
    const struct bpf2socks_runtime_config *config,
    const struct tcp_connection *connection) {
    if (connection->stage != TCP_STAGE_RELAY) {
        if (connection->created_at_ms == 0U || config->connect_timeout_milliseconds == 0U) {
            return BPF2SOCKS_NO_DEADLINE;
        }
        return connection->created_at_ms + config->connect_timeout_milliseconds;
    }
    if (connection->last_activity_ms == 0U || config->tcp_idle_timeout_milliseconds == 0U) {
        return BPF2SOCKS_NO_DEADLINE;
    }
    return connection->last_activity_ms + config->tcp_idle_timeout_milliseconds;
}

static void note_connection_deadline(struct tcp_worker_state *state, const struct tcp_connection *connection) {
    if (connection == NULL || connection->closing) return;
    bpf2socks_deadline_note(&state->next_deadline_ms, connection_deadline(state->worker->config, connection));
}

/* Scans only when the earliest deadline is due, then recomputes it. */
static void expire_tcp_connections(struct tcp_worker_state *state, uint64_t now_ms) {
    if (state == NULL || state->worker == NULL || state->worker->config == NULL) return;
    if (now_ms == 0U || now_ms < state->next_deadline_ms) return;
    state->next_deadline_ms = BPF2SOCKS_NO_DEADLINE;
    const struct bpf2socks_runtime_config *config = state->worker->config;
    for (struct tcp_connection *connection = state->active; connection != NULL;) {
        struct tcp_connection *next = connection->active_next;
        bool relay_established = connection->stage == TCP_STAGE_RELAY;
        if (bpf2socks_deadline_tcp_expired(
                now_ms,
                connection->created_at_ms,
                connection->last_activity_ms,
                relay_established,
                config->connect_timeout_milliseconds,
                config->tcp_idle_timeout_milliseconds)) {
            if (relay_established) {
                ++state->worker->tcp_stats.tcp_idle_timeouts;
                close_connection(state, connection);
            } else {
                /* The upstream never became usable: fail the client's connection. */
                ++state->worker->tcp_stats.tcp_connect_timeouts;
                reset_connection(state, connection, TCP_SIDE_UPSTREAM);
            }
        } else {
            note_connection_deadline(state, connection);
        }
        connection = next;
    }
}

static void publish_tcp_stats_if_due(struct tcp_worker_state *state, uint64_t now_ms, bool force) {
    if (state == NULL || state->worker == NULL || state->worker->config == NULL ||
        !state->worker->config->debug_stats) {
        return;
    }
    if (!force && (now_ms == 0U ||
            (state->next_stats_publish_ms != 0U && now_ms < state->next_stats_publish_ms))) {
        return;
    }
    bpf2socks_bridge_publish_tcp_stats(state->worker);
    if (now_ms != 0U) {
        state->next_stats_publish_ms = now_ms + BPF2SOCKS_TCP_STATS_PUBLISH_MILLISECONDS;
    }
}

static bool reserve_tcp_session(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->tcp_session_budget == NULL) return false;
    struct bpf2socks_tcp_budget *budget = worker->tcp_session_budget;
    size_t used = atomic_load_explicit(&budget->used, memory_order_relaxed);
    while (used < budget->cap) {
        if (atomic_compare_exchange_weak_explicit(
                &budget->used,
                &used,
                used + 1U,
                memory_order_acq_rel,
                memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

static void release_tcp_session_budget(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->tcp_session_budget == NULL) {
        return;
    }
    (void)atomic_fetch_sub_explicit(
        &worker->tcp_session_budget->used,
        1U,
        memory_order_acq_rel);
}

static void release_tcp_session(struct tcp_connection *connection) {
    if (connection == NULL || !connection->session_reserved) return;
    release_tcp_session_budget(connection->worker);
    connection->session_reserved = false;
}

static void tune_tcp_socket(int fd, const struct bpf2socks_runtime_config *config) {
    bpf2socks_socket_tune_tcp_buffers(fd, config);
    bpf2socks_socket_tune_tcp_latency(fd, false);
}

static void tune_upstream_tcp_socket(int fd, const struct bpf2socks_runtime_config *config) {
    bpf2socks_socket_tune_tcp_buffers(fd, config);
    bpf2socks_socket_tune_tcp_latency(fd, true);
}

/*
 * A hotspot client can leave without closing its connections, and idle
 * connections are not timed out by default. Keepalive probes find such a
 * peer instead: after 60 s of silence, six unanswered probes 10 s apart reset
 * the connection. Local clients close with their process and need none.
 */
static void enable_remote_client_keepalive(int fd, const struct sockaddr_storage *peer) {
    if (bpf2socks_sockaddr_is_loopback(peer)) return;
    int on = 1;
    int idle_seconds = 60;
    int interval_seconds = 10;
    int probes = 6;
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle_seconds, sizeof(idle_seconds));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval_seconds, sizeof(interval_seconds));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probes, sizeof(probes));
}

static int connect_nonblocking_addr(
    struct bpf2socks_bridge_worker *worker,
    const struct sockaddr *addr,
    socklen_t addr_len,
    enum tcp_stage *stage) {
    if (addr == NULL || addr_len == 0U || stage == NULL) {
        errno = EINVAL;
        return -1;
    }
    int fd = socket(addr->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    tune_upstream_tcp_socket(fd, worker != NULL ? worker->config : NULL);
    if (bpf2socks_socket_connect(fd, addr, addr_len) == 0) {
        *stage = TCP_STAGE_REQUEST_WRITE;
        return fd;
    }
    if (errno == EINPROGRESS) {
        *stage = TCP_STAGE_CONNECTING;
        return fd;
    }
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
}

static int add_fd(struct tcp_worker_state *state, int fd, struct tcp_fd_ref *ref, uint32_t events) {
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events;
    event.data.ptr = ref;
    if (epoll_ctl(state->worker->epoll_fd, EPOLL_CTL_ADD, fd, &event) != 0) return -1;
    ref->events = events;
    return 0;
}

static int mod_fd(struct tcp_worker_state *state, int fd, struct tcp_fd_ref *ref, uint32_t events) {
    if (ref->events == events) return 0;
    if (events == 0U) {
        if (epoll_ctl(state->worker->epoll_fd, EPOLL_CTL_DEL, fd, NULL) != 0) return -1;
        ref->events = 0U;
        return 0;
    }
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events;
    event.data.ptr = ref;
    int op = ref->events == 0U ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(state->worker->epoll_fd, op, fd, &event) != 0) return -1;
    ref->events = events;
    return 0;
}

static int open_spare_fd(void) {
    return open("/dev/null", O_RDONLY | O_CLOEXEC);
}

static void pause_tcp_listeners(struct tcp_worker_state *state) {
    if (state == NULL || state->listeners_paused) return;
    bool paused = true;
    if (state->listener4_ref.events != 0U &&
        mod_fd(state, state->listener4_ref.fd, &state->listener4_ref, 0U) != 0) {
        paused = false;
    }
    if (state->listener6_ref.fd >= 0 && state->listener6_ref.events != 0U &&
        mod_fd(state, state->listener6_ref.fd, &state->listener6_ref, 0U) != 0) {
        paused = false;
    }
    if (!paused) return;
    state->listeners_paused = true;
    uint64_t now_ms = bpf2socks_now_ms();
    state->listeners_resume_ms = now_ms + BPF2SOCKS_TCP_FD_BACKOFF_MILLISECONDS;
}

static void resume_tcp_listeners_if_due(struct tcp_worker_state *state) {
    if (state == NULL || !state->listeners_paused) return;
    uint64_t now_ms = bpf2socks_now_ms();
    if (now_ms == 0U || now_ms < state->listeners_resume_ms) return;
    if (state->spare_fd < 0) {
        state->spare_fd = open_spare_fd();
        if (state->spare_fd < 0) {
            state->listeners_resume_ms = now_ms + BPF2SOCKS_TCP_FD_BACKOFF_MILLISECONDS;
            return;
        }
    }
    bool resumed = true;
    if (state->listener4_ref.events == 0U &&
        mod_fd(state, state->listener4_ref.fd, &state->listener4_ref, EPOLLIN) != 0) {
        resumed = false;
    }
    if (state->listener6_ref.fd >= 0 && state->listener6_ref.events == 0U &&
        mod_fd(state, state->listener6_ref.fd, &state->listener6_ref, EPOLLIN) != 0) {
        resumed = false;
    }
    if (resumed) {
        state->listeners_paused = false;
        state->listeners_resume_ms = 0U;
    } else {
        state->listeners_resume_ms = now_ms + BPF2SOCKS_TCP_FD_BACKOFF_MILLISECONDS;
    }
}

static void handle_accept_fd_exhaustion(struct tcp_worker_state *state, int listener_fd) {
    if (state == NULL || state->worker == NULL) return;
    ++state->worker->tcp_stats.tcp_fd_exhaustions;
    bpf2socks_close_fd(&state->spare_fd);
    int client;
    do {
        client = bpf2socks_socket_accept4(listener_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
    } while (client < 0 && errno == EINTR);
    if (client >= 0) close(client);
    state->spare_fd = open_spare_fd();
    pause_tcp_listeners(state);
}

static void record_fd_exhaustion(struct tcp_worker_state *state) {
    if (state == NULL || state->worker == NULL) return;
    ++state->worker->tcp_stats.tcp_fd_exhaustions;
    pause_tcp_listeners(state);
}

/*
 * Level-triggered epoll: never request readiness that cannot make progress.
 * EPOLLIN/EPOLLRDHUP are requested only while the side may still be read and
 * its pipe has room; otherwise a readable source with a full pipe, or a
 * half-closed source, would wake the worker continuously.
 */
static uint32_t relay_side_events(bool want_input, bool output_pending) {
    uint32_t events = 0U;
    if (want_input) events |= EPOLLIN | EPOLLRDHUP;
    if (output_pending) events |= EPOLLOUT;
    if (events != 0U) {
        events |= EPOLLERR | EPOLLHUP;
    }
    return events;
}

static bool splice_pipe_wants_input(const struct tcp_splice_pipe *pipe_state) {
    return !pipe_state->input_eof && !pipe_state->input_paused;
}

static bool socket_has_unread_bytes(int fd) {
    int pending = 0;
    return ioctl(fd, FIONREAD, &pending) == 0 && pending > 0;
}

static uint32_t client_events(const struct tcp_connection *connection) {
    uint32_t events = BPF2SOCKS_TCP_HANDSHAKE_CLIENT_EVENTS;
    if (connection->stage == TCP_STAGE_RELAY) {
        events = relay_side_events(
            splice_pipe_wants_input(&connection->client_to_upstream),
            connection->upstream_to_client.queued > 0U);
    }
    return events;
}

static uint32_t upstream_events(const struct tcp_connection *connection) {
    uint32_t events = BPF2SOCKS_TCP_RELAY_EVENTS;
    switch (connection->stage) {
        case TCP_STAGE_CONNECTING:
        case TCP_STAGE_REQUEST_WRITE:
            events |= EPOLLOUT;
            break;
        case TCP_STAGE_REPLY_READ:
            events |= EPOLLIN;
            break;
        case TCP_STAGE_RELAY:
            events = relay_side_events(
                splice_pipe_wants_input(&connection->upstream_to_client),
                connection->client_to_upstream.queued > 0U);
            break;
    }
    return events;
}

static void update_connection_events(struct tcp_worker_state *state, struct tcp_connection *connection) {
    if (connection == NULL || connection->closing) return;
    (void)mod_fd(state, connection->client_fd, &connection->client_ref, client_events(connection));
    (void)mod_fd(state, connection->upstream_fd, &connection->upstream_ref, upstream_events(connection));
}

static int start_handshake(struct tcp_connection *connection) {
    size_t length = bpf2socks_socks5_build_hello(connection->handshake, sizeof(connection->handshake));
    size_t request_length = bpf2socks_socks5_build_connect_request(
        connection->handshake + length,
        sizeof(connection->handshake) - length,
        &connection->target);
    if (length == 0U || request_length == 0U) return -1;
    length += request_length;
    connection->handshake_length = length;
    connection->handshake_offset = 0U;
    connection->stage = TCP_STAGE_REQUEST_WRITE;
    return 0;
}

static int flush_handshake(struct tcp_connection *connection) {
    while (connection->handshake_offset < connection->handshake_length) {
        ssize_t sent = send(
            connection->upstream_fd,
            connection->handshake + connection->handshake_offset,
            connection->handshake_length - connection->handshake_offset,
            MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (sent <= 0) return -1;
        connection->handshake_offset += (size_t)sent;
        connection_touch(connection);
    }
    connection->response_length = 0U;
    connection->stage = TCP_STAGE_REPLY_READ;
    return 0;
}

/*
 * The hello and CONNECT request were pipelined, so read both replies with as
 * few recv() calls as possible. Bytes past the replies are early upstream
 * payload; they are queued into the upstream-to-client pipe.
 */
static int read_pipelined_replies(struct tcp_connection *connection) {
    for (;;) {
        size_t room = sizeof(connection->response) - connection->response_length;
        if (room == 0U) {
            errno = EPROTO;
            return -1;
        }
        ssize_t received = recv(
            connection->upstream_fd,
            connection->response + connection->response_length,
            room,
            MSG_DONTWAIT);
        if (received < 0 && errno == EINTR) continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (received <= 0) return -1;
        connection->response_length += (size_t)received;
        connection_touch(connection);

        const uint8_t *response = connection->response;
        size_t length = connection->response_length;
        if (length >= 2U && (response[0] != 0x05 || response[1] != 0x00)) {
            errno = EPROTO;
            return -1;
        }
        /* The CONNECT reply follows the 2-byte method reply. */
        size_t needed = length > 2U ? bpf2socks_socks5_reply_length(response + 2U, length - 2U) : 0U;
        if (needed != 0U && needed != SIZE_MAX) needed += 2U;
        if (needed == SIZE_MAX) {
            errno = EPROTO;
            return -1;
        }
        if (needed != 0U && length >= needed) {
            connection->response_expected = needed;
            return 1;
        }
        /* A short read drained the socket; wait for the rest. */
        if ((size_t)received < room) return 0;
    }
}

static int finish_pipelined_replies(struct tcp_connection *connection) {
    if (init_connection_splice_pipes(connection) < 0) return -1;
    size_t extra = connection->response_length - connection->response_expected;
    if (extra > 0U) {
        ssize_t written = write(
            connection->upstream_to_client.write_fd,
            connection->response + connection->response_expected,
            extra);
        if (written != (ssize_t)extra) {
            if (written >= 0) errno = EIO;
            return -1;
        }
        connection->upstream_to_client.queued += extra;
    }
    connection->stage = TCP_STAGE_RELAY;
    return 0;
}

static struct tcp_connection *create_connection(
    struct tcp_worker_state *state,
    int client_fd,
    const struct bpf2socks_sockaddr *dst) {
    struct tcp_connection *connection = calloc(1U, sizeof(*connection));
    if (connection == NULL) {
        int saved = errno;
        close(client_fd);
        errno = saved;
        return NULL;
    }
    connection->client_fd = client_fd;
    connection->upstream_fd = -1;
    init_splice_pipe(&connection->client_to_upstream);
    init_splice_pipe(&connection->upstream_to_client);
    connection->worker = state->worker;
    connection->pipe_pool = &state->pipe_pool;
    connection->created_at_ms = bpf2socks_now_ms();
    connection->last_activity_ms = connection->created_at_ms;
    connection->client_ref.connection = connection;
    connection->client_ref.side = TCP_SIDE_CLIENT;
    connection->client_ref.fd = client_fd;
    connection->upstream_ref.connection = connection;
    connection->upstream_ref.side = TCP_SIDE_UPSTREAM;
    connection->target = *dst;

    connection->upstream_fd = connect_nonblocking_addr(
        state->worker,
        (const struct sockaddr *)&state->worker->socks_addr,
        state->worker->socks_addr_len,
        &connection->stage);
    if (connection->upstream_fd < 0) {
        int saved = errno;
        reset_on_close(connection->client_fd);
        free_connection(connection);
        errno = saved;
        return NULL;
    }
    connection->upstream_ref.fd = connection->upstream_fd;
    if (connection->stage == TCP_STAGE_REQUEST_WRITE) {
        /* Connected (or TFO-deferred) already: write the handshake now. */
        if (start_handshake(connection) < 0 || flush_handshake(connection) < 0) {
            int saved = errno;
            reset_on_close(connection->client_fd);
            free_connection(connection);
            errno = saved;
            return NULL;
        }
    }
    return connection;
}

static int client_original_dst(
    int client_fd,
    const struct sockaddr_storage *peer,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_sockaddr *dst) {
    const struct bpf2socks_runtime_config *config = worker->config;
    struct bpf2socks_token_key key;
    struct bpf2socks_original_dst original;
    if (fill_tcp_token_key(client_fd, peer, &key) < 0) return -1;
    if (lookup_original_with_client_fallback(
            config->token_map_fd,
            &key,
            &original,
            &worker->tcp_stats) < 0 &&
        lookup_tcp_original_from_socket(client_fd, config, &original) < 0) {
        return -1;
    }
    return bpf2socks_original_dst_to_sockaddr(&original, dst);
}

static void accept_ready_clients(struct tcp_worker_state *state, int listener_fd) {
    while (!bpf2socks_stop_requested()) {
        struct sockaddr_storage peer;
        socklen_t peer_len = sizeof(peer);
        memset(&peer, 0, sizeof(peer));
        int client = bpf2socks_socket_accept4(
            listener_fd,
            (struct sockaddr *)&peer,
            &peer_len,
            SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (client < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (client < 0 && errno == EINTR) continue;
        if (client < 0) {
            if (errno == EMFILE || errno == ENFILE) {
                handle_accept_fd_exhaustion(state, listener_fd);
                return;
            }
            BPF2SOCKS_LOG_THROTTLED("accept4 failed: errno=%d", errno);
            return;
        }
        ++state->worker->tcp_stats.tcp_accepts;
        tune_tcp_socket(client, state->worker->config);
        enable_remote_client_keepalive(client, &peer);

        struct bpf2socks_sockaddr dst;
        if (client_original_dst(client, &peer, state->worker, &dst) < 0) {
            BPF2SOCKS_LOG_THROTTLED("missing TCP original destination: errno=%d", errno);
            reset_on_close(client);
            close(client);
            continue;
        }
        if (!reserve_tcp_session(state->worker)) {
            ++state->worker->tcp_stats.tcp_drops_capacity;
            reset_on_close(client);
            close(client);
            continue;
        }

        struct tcp_connection *connection = create_connection(state, client, &dst);
        if (connection == NULL) {
            int saved = errno;
            release_tcp_session_budget(state->worker);
            if (saved == EMFILE || saved == ENFILE) {
                record_fd_exhaustion(state);
                return;
            }
            ++state->worker->tcp_stats.tcp_connect_failures;
            BPF2SOCKS_LOG_THROTTLED("SOCKS5 TCP upstream connect failed: errno=%d", saved);
            continue;
        }
        connection->session_reserved = true;

        active_add(state, connection);
        note_connection_deadline(state, connection);
        if (add_fd(state, connection->client_fd, &connection->client_ref, client_events(connection)) != 0 ||
            add_fd(state, connection->upstream_fd, &connection->upstream_ref, upstream_events(connection)) != 0) {
            int saved = errno;
            close_connection(state, connection);
            if (saved == EMFILE || saved == ENFILE) {
                record_fd_exhaustion(state);
                return;
            }
        }
    }
}

static int shutdown_splice_target(int target_fd, struct tcp_splice_pipe *pipe_state) {
    if (!pipe_state->input_eof || pipe_state->queued > 0U || pipe_state->output_shutdown) return 0;
    if (shutdown(target_fd, SHUT_WR) != 0 && errno != ENOTCONN && errno != EPIPE) {
        return -1;
    }
    pipe_state->output_shutdown = true;
    return 0;
}

/*
 * Epoll is level-triggered, so a short splice ends the pass: any data left
 * behind reports EPOLLIN again. Only an EAGAIN with bytes already queued can
 * mean a full pipe, and only then is FIONREAD needed to decide whether to
 * pause input.
 */
static int splice_socket_to_pipe(
    struct tcp_connection *connection,
    int source_fd,
    struct tcp_splice_pipe *pipe_state) {
    if (pipe_state->input_eof) return 0;
    bool moved_data = false;
    while (true) {
        ssize_t moved = splice(
            source_fd,
            NULL,
            pipe_state->write_fd,
            NULL,
            pipe_state->capacity,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (moved > 0) {
            pipe_state->queued += (size_t)moved;
            moved_data = true;
            if ((size_t)moved < pipe_state->capacity) {
                connection_touch(connection);
                return 0;
            }
            continue;
        }
        if (moved == 0) {
            if (moved_data) connection_touch(connection);
            pipe_state->input_eof = true;
            return 0;
        }
        if (errno == EINTR) continue;
        if (moved_data) connection_touch(connection);
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* EAGAIN with unread socket data means the pipe is full. */
            if (pipe_state->queued > 0U && socket_has_unread_bytes(source_fd)) {
                pipe_state->input_paused = true;
            }
            return 0;
        }
        return -1;
    }
}

static int splice_pipe_to_socket(
    struct tcp_connection *connection,
    int target_fd,
    struct tcp_splice_pipe *pipe_state,
    uint64_t *bytes_out) {
    bool moved_data = false;
    while (pipe_state->queued > 0U) {
        size_t chunk = pipe_state->queued;
        if (chunk > pipe_state->capacity) chunk = pipe_state->capacity;
        ssize_t moved = splice(
            pipe_state->read_fd,
            NULL,
            target_fd,
            NULL,
            chunk,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (moved > 0) {
            pipe_state->queued -= (size_t)moved;
            pipe_state->input_paused = false;
            if (bytes_out != NULL) *bytes_out += (uint64_t)moved;
            moved_data = true;
            continue;
        }
        if (moved == 0) {
            if (moved_data) connection_touch(connection);
            return -1;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (moved_data) connection_touch(connection);
        return -1;
    }
    if (moved_data) connection_touch(connection);
    return shutdown_splice_target(target_fd, pipe_state);
}

static bool splice_pipe_complete(const struct tcp_splice_pipe *pipe_state) {
    return pipe_state->input_eof && pipe_state->queued == 0U && pipe_state->output_shutdown;
}

static bool relay_complete(const struct tcp_connection *connection) {
    return splice_pipe_complete(&connection->client_to_upstream) &&
        splice_pipe_complete(&connection->upstream_to_client);
}

/* On failure, *failed_side names the socket that could not be written. */
static int flush_relay_pipes(struct tcp_connection *connection, enum tcp_side *failed_side) {
    if (splice_pipe_to_socket(
            connection,
            connection->upstream_fd,
            &connection->client_to_upstream,
            &connection->worker->tcp_stats.tcp_bytes_client_to_upstream) < 0) {
        *failed_side = TCP_SIDE_UPSTREAM;
        return -1;
    }
    if (splice_pipe_to_socket(
            connection,
            connection->client_fd,
            &connection->upstream_to_client,
            &connection->worker->tcp_stats.tcp_bytes_upstream_to_client) < 0) {
        *failed_side = TCP_SIDE_CLIENT;
        return -1;
    }
    return 0;
}

static void handle_client_event(struct tcp_worker_state *state, struct tcp_connection *connection, uint32_t events) {
    if ((events & EPOLLERR) != 0) {
        reset_connection(state, connection, TCP_SIDE_CLIENT);
    } else if ((events & BPF2SOCKS_TCP_HANDSHAKE_CLIENT_EVENTS) != 0) {
        close_connection(state, connection);
    }
}

static void handle_upstream_handshake(
    struct tcp_worker_state *state,
    struct tcp_connection *connection,
    uint32_t events) {
    if ((events & EPOLLERR) != 0) {
        reset_connection(state, connection, TCP_SIDE_UPSTREAM);
        return;
    }
    /*
     * An upstream that sends its replies, early payload and FIN together
     * reports a hangup along with them. Read what arrived first; the hangup
     * only fails the connection if the replies are still incomplete.
     */
    bool hangup = (events & (EPOLLHUP | EPOLLRDHUP)) != 0;
    bool readable = (events & EPOLLIN) != 0 || hangup;
    int result = 0;
    /*
     * A failed connect surfaces as the first send() error, so no SO_ERROR
     * round trip is needed before writing the handshake.
     */
    if (connection->stage == TCP_STAGE_CONNECTING && (events & EPOLLOUT) != 0) {
        result = start_handshake(connection);
    }
    if (result == 0 && connection->stage == TCP_STAGE_REQUEST_WRITE && (events & EPOLLOUT) != 0) {
        result = flush_handshake(connection);
    }
    if (result == 0 && connection->stage == TCP_STAGE_REPLY_READ && readable) {
        result = read_pipelined_replies(connection);
        result = result > 0 ? finish_pipelined_replies(connection) : result;
    }
    if (result == 0 && hangup && connection->stage != TCP_STAGE_RELAY) {
        errno = ECONNRESET;
        result = -1;
    }
    if (result < 0) {
        /* The SOCKS5 server refused or dropped the connection before relaying. */
        ++state->worker->tcp_stats.tcp_connect_failures;
        reset_connection(state, connection, TCP_SIDE_UPSTREAM);
    }
}

static void handle_splice_relay(
    struct tcp_worker_state *state,
    struct tcp_connection *connection,
    enum tcp_side side,
    uint32_t events) {
    /* A reset or error on one side resets the other instead of ending it with a FIN. */
    if ((events & EPOLLERR) != 0) {
        reset_connection(state, connection, side);
        return;
    }

    if (side == TCP_SIDE_CLIENT) {
        if ((events & EPOLLIN) != 0 &&
            splice_socket_to_pipe(connection, connection->client_fd, &connection->client_to_upstream) < 0) {
            reset_connection(state, connection, TCP_SIDE_CLIENT);
            return;
        }
    } else if (side == TCP_SIDE_UPSTREAM) {
        if ((events & EPOLLIN) != 0 &&
            splice_socket_to_pipe(connection, connection->upstream_fd, &connection->upstream_to_client) < 0) {
            reset_connection(state, connection, TCP_SIDE_UPSTREAM);
            return;
        }
    }

    enum tcp_side failed_side = TCP_SIDE_CLIENT;
    if (flush_relay_pipes(connection, &failed_side) < 0) {
        reset_connection(state, connection, failed_side);
        return;
    }
    if (relay_complete(connection)) {
        close_connection(state, connection);
    }
}

static void handle_connection_event(struct tcp_worker_state *state, struct tcp_fd_ref *ref, uint32_t events) {
    if (ref == NULL) return;
    if (ref->side == TCP_SIDE_LISTENER) {
        if (!state->listeners_paused && (events & EPOLLIN) != 0) accept_ready_clients(state, ref->fd);
        return;
    }
    if (ref->connection == NULL) return;
    struct tcp_connection *connection = ref->connection;
    if (connection->stage == TCP_STAGE_RELAY) {
        handle_splice_relay(state, connection, ref->side, events);
    } else if (ref->side == TCP_SIDE_CLIENT) {
        handle_client_event(state, connection, events);
    } else {
        handle_upstream_handshake(state, connection, events);
    }
    update_connection_events(state, connection);
    note_connection_deadline(state, connection);
}

int bpf2socks_bridge_tcp_run(struct bpf2socks_bridge_worker *worker) {
    if (worker == NULL || worker->tcp4_listener_fd < 0) return -1;
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return -1;
    worker->epoll_fd = epoll_fd;

    struct epoll_event stop_event;
    memset(&stop_event, 0, sizeof(stop_event));
    stop_event.events = EPOLLIN;
    int stop_fd = bpf2socks_stop_event_fd();
    if (stop_fd < 0 || epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_fd, &stop_event) != 0) {
        int saved = stop_fd < 0 ? EINVAL : errno;
        close(epoll_fd);
        worker->epoll_fd = -1;
        errno = saved;
        return -1;
    }

    struct tcp_worker_state state;
    memset(&state, 0, sizeof(state));
    state.worker = worker;
    state.listener4_ref.side = TCP_SIDE_LISTENER;
    state.listener4_ref.fd = worker->tcp4_listener_fd;
    state.listener6_ref.side = TCP_SIDE_LISTENER;
    state.listener6_ref.fd = worker->tcp6_listener_fd;
    state.spare_fd = -1;
    state.next_deadline_ms = BPF2SOCKS_NO_DEADLINE;

    if (add_fd(&state, worker->tcp4_listener_fd, &state.listener4_ref, EPOLLIN) != 0) {
        int saved = errno;
        close(epoll_fd);
        worker->epoll_fd = -1;
        errno = saved;
        return -1;
    }
    if (worker->tcp6_listener_fd >= 0) {
        if (add_fd(&state, worker->tcp6_listener_fd, &state.listener6_ref, EPOLLIN) != 0) {
            int saved = errno;
            close(epoll_fd);
            worker->epoll_fd = -1;
            errno = saved;
            return -1;
        }
    }
    state.spare_fd = open_spare_fd();
    if (state.spare_fd < 0) {
        int saved = errno;
        close(epoll_fd);
        worker->epoll_fd = -1;
        errno = saved;
        return -1;
    }

    int result = 0;
    int wait_errno = 0;
    struct epoll_event events[BPF2SOCKS_TCP_EVENTS];
    while (!bpf2socks_stop_requested()) {
        resume_tcp_listeners_if_due(&state);
        int timeout = bpf2socks_deadline_tcp_wait_timeout(
            state.listeners_paused,
            state.next_deadline_ms,
            bpf2socks_now_ms(),
            worker->config->debug_stats);
        int ready = epoll_wait(epoll_fd, events, BPF2SOCKS_TCP_EVENTS, timeout);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) {
            wait_errno = errno;
            result = -1;
            break;
        }
        if (bpf2socks_stop_requested()) break;
        for (int i = 0; i < ready; ++i) {
            handle_connection_event(&state, events[i].data.ptr, events[i].events);
        }
        uint64_t now_ms = bpf2socks_now_ms();
        resume_tcp_listeners_if_due(&state);
        expire_tcp_connections(&state, now_ms);
        publish_tcp_stats_if_due(&state, now_ms, false);
        free_closed_connections(&state);
    }

    close_all_active(&state);
    close_pipe_pool(&state.pipe_pool);
    publish_tcp_stats_if_due(&state, bpf2socks_now_ms(), true);
    bpf2socks_close_fd(&state.spare_fd);
    close(epoll_fd);
    worker->epoll_fd = -1;
    if (result != 0) errno = wait_errno;
    return result;
}
