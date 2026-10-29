// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_H
#define BPF2SOCKS_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>


/* Enhancement module wire contract; proxy marks include routing bits. */
#define BPF2SOCKS_DNS_MARK_MASK UINT32_C(0x61000000)
#define BPF2SOCKS_DNS_PROXY_DECISION UINT32_C(0x21000000)
#define BPF2SOCKS_DNS_DIRECT_MARK UINT32_C(0x41000000)

#define BPF2SOCKS_MAX_UIDS 8192U
#define BPF2SOCKS_MAX_CIDR_MAP_ENTRIES 512U
#define BPF2SOCKS_MAX_DIRECT_CIDR_MAP_ENTRIES 32768U
#define BPF2SOCKS_MAX_POLICY_CIDRS 512U
#define BPF2SOCKS_MAX_CIDR_TEXT_LEN 64U
#define BPF2SOCKS_MAX_INTERFACES 64U
#define BPF2SOCKS_MAX_INTERFACE_NAME_LEN 32U
#define BPF2SOCKS_MAX_PATH_LEN 512U
#define BPF2SOCKS_UID_SELECTED 1U
#define BPF2SOCKS_UID_BYPASS 2U
#define BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP 1U
#define BPF2SOCKS_MAX_TOKEN_MAP_ENTRIES 65536U
#define BPF2SOCKS_MAX_UDP_PEER_MAP_ENTRIES 65536U
#define BPF2SOCKS_MAX_TCP_PEER_MAP_ENTRIES 65536U
#define BPF2SOCKS_MAX_DEFAULT_NETWORK_MAP_ENTRIES 64U
/* Android fwmark bit set on sockets an app bound to a network explicitly. */
#define BPF2SOCKS_FWMARK_EXPLICIT 0x10000U
/* netId 0 is never a network: its key marks the default network set as known. */
#define BPF2SOCKS_DEFAULT_NETWORK_READY_KEY 0U
#define BPF2SOCKS_DEFAULT_CGROUP_PATH "/sys/fs/cgroup"
#define BPF2SOCKS_DEFAULT_WORKER_COUNT 2U
/* Idle relay pipe pairs each TCP worker may keep open (4 fds per pair). */
#define BPF2SOCKS_TCP_PIPE_POOL_CAP 16U
#define BPF2SOCKS_MAX_WORKER_COUNT 8U
/* 0 leaves TCP socket buffers to kernel autotuning. */
#define BPF2SOCKS_DEFAULT_TCP_BUFFER_SIZE 0U
#define BPF2SOCKS_DEFAULT_MAX_TCP_SESSIONS 4096U
#define BPF2SOCKS_MAX_TCP_SESSIONS 8192U
#define BPF2SOCKS_DEFAULT_CONNECT_TIMEOUT_MILLISECONDS 10000U
#define BPF2SOCKS_MIN_CONNECT_TIMEOUT_MILLISECONDS 1000U
#define BPF2SOCKS_MAX_CONNECT_TIMEOUT_MILLISECONDS 60000U
/* Zero leaves idle relayed TCP open, as the proxy cores do; dead hotspot peers are found by keepalive. */
#define BPF2SOCKS_DEFAULT_TCP_IDLE_TIMEOUT_MILLISECONDS 0U
#define BPF2SOCKS_MIN_TCP_IDLE_TIMEOUT_MILLISECONDS 1000U
#define BPF2SOCKS_MAX_TCP_IDLE_TIMEOUT_MILLISECONDS 3600000U
#define BPF2SOCKS_DEFAULT_UDP_SOCKET_BUFFER_SIZE 524288U
#define BPF2SOCKS_DEFAULT_UDP_BATCH_SIZE 32U
#define BPF2SOCKS_DEFAULT_MAX_UDP_SESSIONS 4096U
#define BPF2SOCKS_DEFAULT_MAX_UDP_BINDINGS 16384U
#define BPF2SOCKS_DEFAULT_UDP_IDLE_TIMEOUT_MILLISECONDS 60000U
#define BPF2SOCKS_MIN_UDP_IDLE_TIMEOUT_MILLISECONDS 1000U
#define BPF2SOCKS_MAX_UDP_IDLE_TIMEOUT_MILLISECONDS 86400000U
/* A closed client's session still delivering replies is checked again after this. */
#define BPF2SOCKS_UDP_RELEASE_RETRY_MILLISECONDS 100U
/*
 * A datagram still queued when its client closed can create a session after
 * the destroy notification was handled; new sessions on a port destroyed this
 * recently, or while notifications were lost, are checked once.
 */
#define BPF2SOCKS_UDP_RELEASE_RECENT_MILLISECONDS 2000U
/* Receive queue of each worker's UDP destroy notification socket. */
#define BPF2SOCKS_UDP_DESTROY_EVENTS_RCVBUF (1024U * 1024U)
#define BPF2SOCKS_MIN_UDP_PENDING_BYTES (128U * 1024U)
#define BPF2SOCKS_DEFAULT_MAX_UDP_PENDING_BYTES (64U * 1024U * 1024U)
#define BPF2SOCKS_MAX_UDP_PENDING_BYTES (128U * 1024U * 1024U)
#define BPF2SOCKS_DEFAULT_DNS_TRANSACTION_TIMEOUT_MILLISECONDS 60000U
#define BPF2SOCKS_MIN_DNS_TRANSACTION_TIMEOUT_MILLISECONDS 1000U
#define BPF2SOCKS_MAX_DNS_TRANSACTION_TIMEOUT_MILLISECONDS 600000U
#define BPF2SOCKS_DEFAULT_NOFILE_LIMIT 65535U
#define BPF2SOCKS_DEFAULT_TOKEN_IPV4_PREFIX "127.128.0.0/9"
#define BPF2SOCKS_TOKEN_IPV4_PREFIX_BITS 9U
#define BPF2SOCKS_DEFAULT_TOKEN_IPV6_PREFIX "fd7a:7374:6572:6973::/64"
#define BPF2SOCKS_TOKEN_IPV6_PREFIX_BITS 64U

#define BPF2SOCKS_MODE_BLACKLIST 0U
#define BPF2SOCKS_MODE_WHITELIST 1U
#define BPF2SOCKS_MODE_GLOBAL 2U

#define BPF2SOCKS_PROTO_TCP 6U
#define BPF2SOCKS_PROTO_UDP 17U

struct bpf2socks_lpm4_key {
    uint32_t prefixlen;
    uint32_t addr;
};

struct bpf2socks_lpm6_key {
    uint32_t prefixlen;
    uint8_t addr[16];
};

struct bpf2socks_policy_config {
    uint32_t mode;
    bool bypass_direct_cidrs;
    bool enable_ipv6;
    bool enable_dns_hijack;
    bool enable_dns_enhancement;
    char direct_cidr_path_v4[BPF2SOCKS_MAX_PATH_LEN];
    char direct_cidr_path_v6[BPF2SOCKS_MAX_PATH_LEN];
    uint32_t uids[BPF2SOCKS_MAX_UIDS];
    size_t uid_count;
    uint32_t bypass_uids[BPF2SOCKS_MAX_UIDS];
    size_t bypass_uid_count;
    bool self_bypass_gid_enabled;
    uint32_t self_bypass_gid;
    size_t hotspot_interface_count;
    char ignored_interfaces[BPF2SOCKS_MAX_INTERFACES][BPF2SOCKS_MAX_INTERFACE_NAME_LEN];
    size_t ignored_interface_count;
    char proxy_private_cidrs_v4[BPF2SOCKS_MAX_POLICY_CIDRS][BPF2SOCKS_MAX_CIDR_TEXT_LEN];
    size_t proxy_private_cidr_v4_count;
    char bypass_private_cidrs_v4[BPF2SOCKS_MAX_POLICY_CIDRS][BPF2SOCKS_MAX_CIDR_TEXT_LEN];
    size_t bypass_private_cidr_v4_count;
    char proxy_private_cidrs_v6[BPF2SOCKS_MAX_POLICY_CIDRS][BPF2SOCKS_MAX_CIDR_TEXT_LEN];
    size_t proxy_private_cidr_v6_count;
    char bypass_private_cidrs_v6[BPF2SOCKS_MAX_POLICY_CIDRS][BPF2SOCKS_MAX_CIDR_TEXT_LEN];
    size_t bypass_private_cidr_v6_count;
};

struct bpf2socks_sockaddr {
    int family;
    uint16_t port;
    uint8_t addr[16];
};

struct bpf2socks_udp_msg {
    struct bpf2socks_sockaddr addr;
    uint8_t *payload;
    size_t payload_len;
    /* Receive only: errno-style reason this datagram is unusable, or 0. */
    int error;
};

struct bpf2socks_token_key {
    uint8_t family;
    uint8_t protocol;
    uint16_t token_port;
    uint8_t token_addr[16];
    uint16_t client_port;
    uint16_t reserved;
    uint8_t client_addr[16];
};

struct bpf2socks_original_dst {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
    uint8_t flags;
    uint8_t reserved[3];
};

struct bpf2socks_udp_peer_key {
    uint64_t cookie;
    uint8_t family;
    uint8_t reserved[7];
};

struct bpf2socks_udp_peer_value {
    uint8_t family;
    uint8_t protocol;
    uint16_t port;
    uint8_t addr[16];
};

struct bpf2socks_runtime_config {
    char socks_host[128];
    uint16_t socks_port;
    char listen_host[64];
    uint16_t listen_port;
    char pinned_object_dir[BPF2SOCKS_MAX_PATH_LEN];
    char cgroup_path[BPF2SOCKS_MAX_PATH_LEN];
    bool enable_ipv6;
    bool enable_dns_hijack;
    bool debug_stats;
    uint8_t token_ipv4_prefix[4];
    uint32_t token_ipv4_prefix_bits;
    uint8_t token_ipv6_prefix[16];
    uint32_t token_ipv6_prefix_bits;
    uint32_t worker_count;
    uint32_t tcp_buffer_size;
    uint32_t max_tcp_sessions;
    uint32_t connect_timeout_milliseconds;
    uint32_t tcp_idle_timeout_milliseconds;
    uint32_t udp_socket_buffer_size;
    uint32_t udp_batch_size;
    uint32_t max_udp_sessions;
    uint32_t max_udp_bindings;
    uint32_t udp_idle_timeout_milliseconds;
    uint32_t max_udp_pending_bytes;
    uint32_t dns_transaction_timeout_milliseconds;
    int token_map_fd;
    int reuseport_tcp4_map_fd;
    int reuseport_udp4_map_fd;
    int reuseport_tcp6_map_fd;
    int reuseport_udp6_map_fd;
    int reuseport_prog_fd;
};

#endif
