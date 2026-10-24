// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_INTERNAL_H
#define BPF2SOCKS_BRIDGE_INTERNAL_H

#include "bpf2socks.h"
#include "bridge/stats.h"
#include "bridge/udp_budget.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/socket.h>
#include <time.h>

#define BPF2SOCKS_UDP_BUFFER_SIZE 65535U
#define BPF2SOCKS_SESSION_HASH_BUCKETS 4096U
#define BPF2SOCKS_MAX_SOCKS5_UDP_HEADER 22U
/* Wait cap used only while debug statistics are published. */
#define BPF2SOCKS_WORKER_TIMED_WAIT_MILLISECONDS 1000
/* Fallback retry while descriptors held by other processes keep accept() failing. */
#define BPF2SOCKS_TCP_FD_BACKOFF_MILLISECONDS 1000
#define BPF2SOCKS_NO_DEADLINE UINT64_MAX
#define BPF2SOCKS_CACHE_LINE_SIZE 64

struct bpf2socks_udp_relay_registry;

struct bpf2socks_udp_downlink_channel;

struct bpf2socks_tcp_budget {
    size_t cap;
    atomic_size_t used;
};

struct bpf2socks_bridge_worker {
    uint32_t id;
    int tcp4_listener_fd;
    int tcp6_listener_fd;
    int udp4_listener_fd;
    int udp6_listener_fd;
    int epoll_fd;
    struct sockaddr_storage socks_addr;
    socklen_t socks_addr_len;
    const struct bpf2socks_runtime_config *config;
    struct bpf2socks_tcp_budget *tcp_session_budget;
    size_t udp_session_cap;
    size_t udp_binding_cap;
    struct bpf2socks_udp_budget *udp_pending_budget;
    struct bpf2socks_udp_relay_registry *udp_relay_registry;
    /*
     * Each worker's TCP and UDP threads count into their own copy, kept on
     * separate cache lines so hot counters never bounce between the two.
     */
    _Alignas(BPF2SOCKS_CACHE_LINE_SIZE) struct bpf2socks_bridge_stats tcp_stats;
    _Alignas(BPF2SOCKS_CACHE_LINE_SIZE) struct bpf2socks_bridge_stats udp_stats;
    _Alignas(BPF2SOCKS_CACHE_LINE_SIZE) struct bpf2socks_bridge_stats stats_snapshot;
    pthread_mutex_t stats_snapshot_mutex;
    bool stats_snapshot_mutex_initialized;
};
bool bpf2socks_deadline_tcp_expired(
    uint64_t now_ms,
    uint64_t created_at_ms,
    uint64_t last_activity_ms,
    bool relay_established,
    uint32_t connect_timeout_ms,
    uint32_t idle_timeout_ms);
void bpf2socks_deadline_note(uint64_t *next_deadline_ms, uint64_t deadline_ms);
int bpf2socks_deadline_tcp_wait_timeout(
    bool listeners_paused,
    uint64_t next_deadline_ms,
    uint64_t now_ms,
    bool debug_stats);
int bpf2socks_deadline_udp_wait_timeout(
    uint64_t next_deadline_ms,
    uint64_t now_ms,
    bool debug_stats);
void bpf2socks_bridge_publish_tcp_stats(struct bpf2socks_bridge_worker *worker);
void bpf2socks_bridge_publish_udp_stats(struct bpf2socks_bridge_worker *worker);
/* Publishes aggregated stats next to pid_path about once a second until stop. */
int bpf2socks_bridge_stats_start(
    const char *pid_path,
    struct bpf2socks_bridge_worker *workers,
    uint32_t worker_count,
    pthread_t *thread);
int bpf2socks_bridge_udp_run(struct bpf2socks_bridge_worker *worker);
int bpf2socks_bridge_tcp_run(struct bpf2socks_bridge_worker *worker);


#endif
