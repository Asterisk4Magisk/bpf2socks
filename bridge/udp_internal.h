// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BRIDGE_UDP_INTERNAL_H
#define BPF2SOCKS_BRIDGE_UDP_INTERNAL_H

#include "bpf2socks.h"
#include "bridge/dns.h"
#include "bridge/internal.h"
#include "bridge/udp_binding_index.h"
#include "bridge/udp_budget.h"
#include "bridge/udp_downlink_queue.h"
#include "bridge/udp_relay_registry.h"
#include "core/token.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>

struct bpf2socks_udp_reply_binding {
    bool used;
    struct bpf2socks_sockaddr original_dst;
    uint8_t token_addr[16];
    bool connected_udp_token;
    int reply_fd;
    bool reply_raw;
    uint64_t reply_fd_generation;
    uint64_t last_seen_ms;
    size_t downlink_pending_count;
    struct bpf2socks_udp_client_session *owner;
    struct bpf2socks_udp_reply_binding *next;
    struct bpf2socks_udp_reply_binding *lru_prev;
    struct bpf2socks_udp_reply_binding *lru_next;
    struct bpf2socks_udp_reply_binding *global_lru_prev;
    struct bpf2socks_udp_reply_binding *global_lru_next;
    struct bpf2socks_udp_reply_binding *free_next;
    struct bpf2socks_udp_reply_binding *hash_next;
};

struct bpf2socks_udp_pending_packet {
    struct bpf2socks_sockaddr original_dst;
    uint8_t *payload;
    size_t payload_len;
    size_t allocation_bytes;
    struct bpf2socks_udp_pending_packet *next;
};

enum bpf2socks_udp_session_stage {
    BPF2SOCKS_UDP_SESSION_UNUSED,
    BPF2SOCKS_UDP_SESSION_CONNECTING,
    BPF2SOCKS_UDP_SESSION_ASSOC_WRITE,
    BPF2SOCKS_UDP_SESSION_ASSOC_READ_HELLO,
    BPF2SOCKS_UDP_SESSION_ASSOC_READ_RESPONSE,
    BPF2SOCKS_UDP_SESSION_READY,
};

struct bpf2socks_udp_client_session {
    bool used;
    enum bpf2socks_udp_session_stage stage;
    enum bpf2socks_token_lookup_mode token_lookup_mode;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int tcp_fd;
    int udp_fd;
    struct sockaddr_storage relay_addr;
    socklen_t relay_addr_len;
    /* udp_fd is connect()ed to relay_addr: send without a destination. */
    bool relay_connected;
    uint64_t last_seen_ms;
    /* Relay port owned in the registry while relay_port_claimed. */
    uint16_t relay_port;
    bool relay_port_claimed;
    uint8_t associate_retries;
    /* When to re-check a closed client still receiving replies; 0 means not pending. */
    uint64_t release_retry_ms;
    uint8_t associate_write_buf[32];
    size_t associate_write_len;
    size_t associate_write_offset;
    uint8_t associate_read_buf[4 + 255 + 2];
    size_t associate_read_len;
    size_t associate_read_expected;
    struct bpf2socks_udp_pending_packet *pending_head;
    struct bpf2socks_udp_pending_packet *pending_tail;
    size_t pending_count;
    struct bpf2socks_udp_downlink_channel *downlink_channels;
    size_t downlink_pending_count;
    bool downlink_paused;
    bool downlink_waiting_budget;
    struct bpf2socks_udp_reply_binding *bindings;
    struct bpf2socks_udp_reply_binding *binding_lru_head;
    struct bpf2socks_udp_reply_binding *binding_lru_tail;
    size_t binding_count;
    struct bpf2socks_udp_client_session *next;
    struct bpf2socks_udp_client_session *lru_prev;
    struct bpf2socks_udp_client_session *lru_next;
    struct bpf2socks_udp_client_session *free_next;
    /* Sessions still in the SOCKS5 handshake, oldest first, for its deadline. */
    uint64_t handshake_started_ms;
    bool handshake_linked;
    struct bpf2socks_udp_client_session *handshake_prev;
    struct bpf2socks_udp_client_session *handshake_next;
};

/* State shared by the UDP worker's modules; each worker thread owns one bpf2socks_udp_state. */

#define BPF2SOCKS_DNS_CHANNELS_PER_WORKER 2U
#define BPF2SOCKS_DNS_MAX_TRANSACTIONS_PER_WORKER 8192U
#define BPF2SOCKS_DNS_CHANNEL_REBUILD_DELAY_MILLISECONDS 1000ULL
#define BPF2SOCKS_DNS_MAX_EXPIRE_PER_LOOP 64U
#define BPF2SOCKS_UDP_STATS_PUBLISH_MILLISECONDS 250U
/* Bound of the stack arrays that hold one recvmmsg/sendmmsg batch. */
#define BPF2SOCKS_UDP_MAX_BATCH 64U

#define BPF2SOCKS_DNS_HANDSHAKE_TIMEOUT_MILLISECONDS 10000U

struct bpf2socks_udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct bpf2socks_udp_client_packet {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int token_family;
    uint8_t token_addr[16];
    bool has_original_dst;
    bool original_from_socket;
    bool connected_udp_token;
    enum bpf2socks_token_lookup_mode token_lookup_mode;
    struct bpf2socks_sockaddr original_dst;
    uint8_t *payload;
    size_t payload_len;
};

struct bpf2socks_udp_downlink_channel;

enum bpf2socks_udp_fd_kind {
    BPF2SOCKS_UDP_FD_LISTENER4,
    BPF2SOCKS_UDP_FD_LISTENER6,
    BPF2SOCKS_UDP_FD_SESSION_CONTROL,
    BPF2SOCKS_UDP_FD_SESSION_RELAY,
    BPF2SOCKS_UDP_FD_DNS_CONTROL,
    BPF2SOCKS_UDP_FD_DNS_RELAY,
    BPF2SOCKS_UDP_FD_DOWNLINK,
    BPF2SOCKS_UDP_FD_BUDGET_WAKE,
    BPF2SOCKS_UDP_FD_DESTROY_EVENTS,
};

struct bpf2socks_udp_fd_ref {
    enum bpf2socks_udp_fd_kind kind;
    int fd;
    struct bpf2socks_udp_client_session *session;
    struct bpf2socks_udp_downlink_channel *downlink;
    uint32_t dns_channel_index;
};

struct bpf2socks_udp_session_fd_refs {
    struct bpf2socks_udp_fd_ref control;
    struct bpf2socks_udp_fd_ref relay;
};

enum bpf2socks_udp_dns_stage {
    BPF2SOCKS_UDP_DNS_IDLE,
    BPF2SOCKS_UDP_DNS_CONNECTING,
    BPF2SOCKS_UDP_DNS_HELLO_WRITE,
    BPF2SOCKS_UDP_DNS_HELLO_READ,
    BPF2SOCKS_UDP_DNS_ASSOC_WRITE,
    BPF2SOCKS_UDP_DNS_ASSOC_READ,
    BPF2SOCKS_UDP_DNS_READY,
};

struct bpf2socks_udp_dns_channel {
    uint32_t index;
    int tcp_fd;
    int udp_fd;
    bool available;
    enum bpf2socks_udp_dns_stage stage;
    uint64_t stage_started_ms;
    uint64_t next_rebuild_ms;
    uint8_t write_buf[4 + 16 + 2];
    size_t write_len;
    size_t write_offset;
    uint8_t read_buf[4 + 1 + 255 + 2];
    size_t read_len;
    uint16_t relay_port;
    bool relay_port_claimed;
    bool relay_paused;
    struct sockaddr_storage relay_addr;
    socklen_t relay_addr_len;
    bool relay_connected;
    struct bpf2socks_udp_fd_ref control_ref;
    struct bpf2socks_udp_fd_ref relay_ref;
};

struct bpf2socks_udp_send_batch {
    struct bpf2socks_udp_client_session *session;
    struct bpf2socks_udp_msg messages[BPF2SOCKS_UDP_MAX_BATCH];
    unsigned int count;
};

struct bpf2socks_udp_downlink_batch {
    int fd;
    bool use_pktinfo;
    struct bpf2socks_udp_client_session *session;
    struct bpf2socks_udp_reply_binding *bindings[BPF2SOCKS_UDP_MAX_BATCH];
    const struct bpf2socks_udp_msg *messages[BPF2SOCKS_UDP_MAX_BATCH];
    unsigned int count;
};

struct bpf2socks_udp_downlink_packet {
    struct bpf2socks_udp_downlink_queue_node queue_node;
    struct bpf2socks_udp_reply_binding *binding;
    size_t payload_len;
    size_t allocation_bytes;
    uint8_t payload[];
};

struct bpf2socks_udp_downlink_channel {
    struct bpf2socks_udp_downlink_channel *next;
    struct bpf2socks_udp_fd_ref ref;
    struct bpf2socks_udp_downlink_queue queue;
    struct bpf2socks_udp_reply_binding *source_binding;
    int fd;
    int source_fd;
    uint64_t source_binding_generation;
    bool use_pktinfo;
    bool raw;
};

/*
 * Per-worker cache of token map lookups. Tokens are stable per connected UDP
 * socket, per TC hotspot flow, and per flow for sendmsg() tokens, so most
 * datagrams can skip the bpf() syscall. A short lifetime bounds how long a
 * token that the kernel evicted and reassigned could be misresolved.
 */
#define BPF2SOCKS_UDP_TOKEN_CACHE_SIZE 4096U
#define BPF2SOCKS_UDP_TOKEN_CACHE_TTL_MILLISECONDS 1000U
#define BPF2SOCKS_UDP_TOKEN_NOTICES_PER_SECOND 64U

struct bpf2socks_udp_token_cache_entry {
    struct bpf2socks_token_key key;
    struct bpf2socks_original_dst original;
    uint64_t expires_ms;
    enum bpf2socks_token_lookup_mode mode;
};

struct bpf2socks_udp_state {
    struct bpf2socks_udp_token_cache_entry *token_cache;
    struct bpf2socks_udp_client_session *sessions;
    struct bpf2socks_udp_client_session *free_sessions;
    struct bpf2socks_udp_reply_binding *bindings;
    struct bpf2socks_udp_reply_binding *free_bindings;
    struct bpf2socks_udp_session_fd_refs *session_refs;
    struct epoll_event *events;
    struct bpf2socks_udp_client_session **session_buckets;
    struct bpf2socks_udp_client_session *lru_head;
    struct bpf2socks_udp_client_session *lru_tail;
    struct bpf2socks_udp_client_session *handshake_head;
    struct bpf2socks_udp_client_session *handshake_tail;
    struct bpf2socks_udp_reply_binding *binding_lru_head;
    struct bpf2socks_udp_reply_binding *binding_lru_tail;
    struct bpf2socks_udp_binding_index binding_index;
    struct bpf2socks_udp_downlink_channel *retired_downlink_channels;
    struct bpf2socks_udp_fd_ref listener4_ref;
    struct bpf2socks_udp_fd_ref listener6_ref;
    struct bpf2socks_udp_fd_ref budget_wake_ref;
    struct bpf2socks_udp_fd_ref destroy_events_ref;
    struct bpf2socks_udp_dns_channel dns_channels[BPF2SOCKS_DNS_CHANNELS_PER_WORKER];
    struct bpf2socks_dns_table dns_table;
    int dns_raw4_fd;
    int dns_raw6_fd;
    /* Raw ICMP sockets that tell a local client its token is unknown. */
    int token_notice4_fd;
    int token_notice6_fd;
    uint64_t token_notice_window_ms;
    uint32_t token_notice_count;
    int epoll_fd;
    int budget_wake_fd;
    /* Earliest session/binding/DNS deadline found by the last maintenance pass. */
    uint64_t next_deadline_ms;
    size_t session_cap;
    size_t session_count;
    size_t binding_cap;
    size_t binding_count;
    struct bpf2socks_udp_budget *pending_budget;
    size_t downlink_read_reservation;
    struct bpf2socks_udp_downlink_waiter_tracker downlink_budget_waiters;
    uint32_t worker_id;
    size_t event_cap;
    uint32_t next_dns_channel;
    struct bpf2socks_udp_relay_registry *relay_registry;
    /* Kernel notifications of destroyed UDP sockets (sock_diag multicast). */
    int destroy_events_fd;
    /* Ports whose local clients may be gone, consumed by release_flagged_sessions. */
    uint8_t *released_ports;
    /* Earliest release_retry_ms of any session; NO_DEADLINE when none. */
    uint64_t release_retry_due_ms;
    /* Per port: low 32 bits of the time its last destroy notification was handled (0: never). */
    uint32_t *port_destroyed_ms;
    /* Until then every new local session is checked: notifications were lost. */
    uint64_t check_new_sessions_until_ms;
    /*
     * Every UDP close in the system is notified; with no local session to
     * release the worker stops watching, so other apps' sockets cannot wake it.
     */
    size_t local_session_count;
    bool destroy_events_armed;
    /* Datagrams moved per recvmmsg/sendmmsg call. */
    uint32_t batch_size;
    uint64_t idle_timeout_ms;
};

/* bridge/udp.c */
bool bpf2socks_udp_relay_skip_unusable(
    struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_msg *message);

/* bridge/udp_downlink.c */
uint32_t bpf2socks_udp_checksum_add_bytes(uint32_t sum, const void *data, size_t len);
uint16_t bpf2socks_udp_checksum_fold(uint32_t sum);
int bpf2socks_udp_raw_send4(
    int fd,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    const uint8_t *payload,
    size_t payload_len);
int bpf2socks_udp_raw_send6(
    int fd,
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    const uint8_t *payload,
    size_t payload_len);
int bpf2socks_udp_raw_reply_socket_create4(void);
int bpf2socks_udp_raw_reply_socket_create6(void);
int bpf2socks_udp_reply_socket_create(const struct bpf2socks_sockaddr *original, bool *raw_socket);
size_t bpf2socks_udp_downlink_max_allocation(void);
void bpf2socks_udp_downlink_release_reservation(struct bpf2socks_udp_state *state);
int bpf2socks_udp_downlink_reserve_slots(struct bpf2socks_udp_state *state, uint32_t *batch);
struct bpf2socks_udp_downlink_channel *bpf2socks_udp_downlink_find_channel(
    const struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_reply_binding *binding,
    int source_fd,
    bool use_pktinfo,
    bool raw);
int bpf2socks_udp_downlink_set_paused(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    bool paused);
void bpf2socks_udp_downlink_resume_budget_waiters(struct bpf2socks_udp_state *state);
void bpf2socks_udp_downlink_free_retired(struct bpf2socks_udp_state *state);
void bpf2socks_udp_downlink_release_session(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session);
int bpf2socks_udp_downlink_queue_packet(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_msg *message,
    int source_fd,
    bool use_pktinfo,
    bool raw);
void bpf2socks_udp_downlink_batch_init(struct bpf2socks_udp_downlink_batch *batch);
int bpf2socks_udp_downlink_flush_channel(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_downlink_channel *channel);
int bpf2socks_udp_downlink_batch_flush(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_downlink_batch *batch,
    struct bpf2socks_bridge_worker *worker);
int bpf2socks_udp_downlink_batch_queue(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_downlink_batch *batch,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding,
    const struct bpf2socks_udp_msg *message,
    int fd,
    bool use_pktinfo);

/* bridge/udp_session.c */
bool bpf2socks_udp_control_fd_is_healthy(int fd);
bool bpf2socks_udp_control_event_is_failure(int fd, uint32_t events);
bool bpf2socks_udp_packet_needs_original_reply_socket(const struct bpf2socks_udp_client_packet *packet);
bool bpf2socks_udp_packet_uses_connected_token(const struct bpf2socks_udp_client_packet *packet);
void bpf2socks_udp_lru_touch(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session);
void bpf2socks_udp_handshake_add_tail(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint64_t now_ms);
void bpf2socks_udp_handshake_remove(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session);
void bpf2socks_udp_binding_lru_touch(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_reply_binding *binding);
void bpf2socks_udp_binding_close_reply(struct bpf2socks_udp_reply_binding *binding);
void bpf2socks_udp_binding_set_reply(
    struct bpf2socks_udp_reply_binding *binding,
    int fd,
    bool reply_raw);
size_t bpf2socks_udp_session_index(const struct bpf2socks_udp_state *state, const struct bpf2socks_udp_client_session *session);
int bpf2socks_udp_epoll_add_events(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref, uint32_t events);
int bpf2socks_udp_epoll_modify(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref, uint32_t events);
int bpf2socks_udp_epoll_add(struct bpf2socks_udp_state *state, int fd, struct bpf2socks_udp_fd_ref *ref);
void bpf2socks_udp_epoll_remove(struct bpf2socks_udp_state *state, int fd);
int bpf2socks_udp_epoll_add_session_control(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session, uint32_t events);
int bpf2socks_udp_epoll_switch_session_to_relay(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session);
void bpf2socks_udp_session_release_pending(struct bpf2socks_udp_state *state, struct bpf2socks_udp_pending_packet *packet);
int bpf2socks_udp_session_queue_pending(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *original_dst,
    const uint8_t *payload,
    size_t payload_len,
    size_t payload_cap);
void bpf2socks_udp_session_close(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session);
struct bpf2socks_udp_client_session *bpf2socks_udp_session_find(
    struct bpf2socks_udp_state *state,
    const struct sockaddr_storage *client_addr,
    socklen_t client_addr_len);
void bpf2socks_udp_session_drop(struct bpf2socks_udp_state *state, struct bpf2socks_udp_client_session *session);
void bpf2socks_udp_session_control_event(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint32_t events);
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_find(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *original,
    struct bpf2socks_bridge_worker *worker);
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_create_for_packet(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_client_packet *packet,
    struct bpf2socks_bridge_worker *worker);
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_create_fullcone(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_sockaddr *remote,
    struct bpf2socks_bridge_worker *worker);
bool bpf2socks_udp_binding_has_token(const struct bpf2socks_udp_reply_binding *binding);
struct bpf2socks_udp_reply_binding *bpf2socks_udp_binding_find_by_domain_port(
    struct bpf2socks_udp_client_session *session,
    uint16_t port);
struct bpf2socks_udp_client_session *bpf2socks_udp_session_get(
    struct bpf2socks_udp_state *state,
    const struct bpf2socks_udp_client_packet *packet,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session);
void bpf2socks_udp_session_expire_handshakes(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms);
void bpf2socks_udp_session_expire_idle(struct bpf2socks_udp_state *state);
void bpf2socks_udp_binding_expire_idle(struct bpf2socks_udp_state *state, struct bpf2socks_bridge_worker *worker);

/* bridge/udp_associate.c */
int bpf2socks_udp_associate_build_request(struct bpf2socks_udp_client_session *session);
int bpf2socks_udp_associate_open(
    const struct sockaddr *socks_addr,
    socklen_t socks_addr_len,
    enum bpf2socks_udp_session_stage *stage);
bool bpf2socks_udp_relay_connect(int udp_fd, const struct sockaddr_storage *relay_addr, socklen_t relay_addr_len);
const struct sockaddr *bpf2socks_udp_relay_destination(
    const struct sockaddr_storage *relay_addr,
    bool relay_connected);
int bpf2socks_udp_relay_send_batch(
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    const struct bpf2socks_udp_msg *messages,
    unsigned int count);
uint16_t bpf2socks_udp_sockaddr_port(const struct sockaddr_storage *addr);
bool bpf2socks_udp_relay_port_needs_claim(const struct bpf2socks_bridge_worker *worker, uint16_t relay_port);
int bpf2socks_udp_associate_advance(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_session *session,
    uint32_t events);

/* bridge/udp_token.c */
int bpf2socks_udp_token_lookup_original(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_packet *packet,
    enum bpf2socks_token_lookup_mode preference,
    uint64_t now_ms);
int bpf2socks_udp_token_recover_connected(
    struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_client_session *session,
    struct bpf2socks_udp_client_packet *packet);
void bpf2socks_udp_token_notify_unknown(
    struct bpf2socks_udp_state *state,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_udp_client_packet *packet,
    uint64_t now_ms);
void bpf2socks_udp_token_delete_closed_client(
    const struct bpf2socks_bridge_worker *worker,
    const struct bpf2socks_udp_client_session *session);
int bpf2socks_udp_token_parse_cmsgs(
    struct msghdr *msg,
    const struct bpf2socks_runtime_config *config,
    struct bpf2socks_udp_client_packet *packet);

/* bridge/udp_dns.c */
bool bpf2socks_udp_dns_is_candidate(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_udp_client_packet *packet);
void bpf2socks_udp_dns_close_channel(struct bpf2socks_udp_state *state, struct bpf2socks_udp_dns_channel *channel, uint64_t now_ms);
void bpf2socks_udp_dns_expire_transactions(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms);
void bpf2socks_udp_dns_control_event(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint32_t events,
    uint64_t now_ms);
void bpf2socks_udp_dns_expire_handshakes(
    struct bpf2socks_udp_state *state,
    uint64_t now_ms);
int bpf2socks_udp_dns_prepare_query(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_client_packet *packet,
    const struct bpf2socks_dns_packet_info *info,
    uint64_t now_ms,
    struct bpf2socks_dns_transaction **out_tx,
    uint32_t *out_channel_index,
    struct bpf2socks_udp_msg *out_message);
void bpf2socks_udp_dns_flush_outgoing(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_dns_transaction **transactions,
    uint32_t *channel_indices,
    struct bpf2socks_udp_msg *messages,
    unsigned int count);
void bpf2socks_udp_dns_handle_upstream(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    struct bpf2socks_udp_dns_channel *channel,
    uint8_t *upstream_packets);

/* bridge/udp_release.c */
void bpf2socks_udp_release_handle_events(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms);
void bpf2socks_udp_release_arm(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms);
void bpf2socks_udp_release_disarm_if_idle(struct bpf2socks_udp_state *state);
void bpf2socks_udp_release_note_new_session(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_udp_client_session *session,
    uint64_t now_ms);
void bpf2socks_udp_release_retry(
    struct bpf2socks_udp_state *state,
    struct bpf2socks_bridge_worker *worker,
    uint64_t now_ms);

#endif
