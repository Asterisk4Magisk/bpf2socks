// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BPF_RUNTIME_H
#define BPF2SOCKS_BPF_RUNTIME_H

#include "bpf2socks.h"

#include <stdbool.h>
#include <stddef.h>

struct bpf2socks_interface_runtime;
struct bpf2socks_network_runtime;

struct bpf2socks_bpf_runtime {
    int cgroup_fd;
    int uid_map_fd;
    int proxy_cidr4_map_fd;
    int bypass_private_cidr4_map_fd;
    int local_interface_cidr4_map_fd;
    int direct_cidr4_map_fd;
    int proxy_cidr6_map_fd;
    int bypass_private_cidr6_map_fd;
    int local_interface_cidr6_map_fd;
    int direct_cidr6_map_fd;
    int ignored_ifindex_map_fd;
    int ignored_route_cidr4_map_fd;
    int ignored_route_cidr6_map_fd;
    int token_map_fd;
    int udp_peer_map_fd;
    int tcp_peer_map_fd;
    int default_network_map_fd;
    int tc_runtime_control_map_fd;
    int tc_original_to_token_map_fd;
    int tc_token_to_original_map_fd;
    int tc_scratch_map_fd;
    int tc_fragment_map_fd;
    int udp6_recovery_map_fd;
    int udp6_record_prog_fd;
    int udp6_recover_prog_fd;
    bool udp6_recovery_attached;
    bool udp6_recovery_qdisc_created;
    int reuseport_tcp4_map_fd;
    int reuseport_udp4_map_fd;
    int reuseport_tcp6_map_fd;
    int reuseport_udp6_map_fd;
    int tc_ingress_prog_fd;
    int tc_egress_prog_fd;
    int reuseport_prog_fd;
    int connect4_prog_fd;
    int connect6_prog_fd;
    int connect6_v4mapped_prog_fd;
    int udp4_sendmsg_prog_fd;
    int udp6_sendmsg_prog_fd;
    int udp6_v4mapped_sendmsg_prog_fd;
    int udp4_getpeername_prog_fd;
    int udp6_getpeername_prog_fd;
    int udp4_recvmsg_prog_fd;
    int udp6_recvmsg_prog_fd;
    int udp6_v4mapped_recvmsg_prog_fd;
    struct bpf2socks_interface_runtime *interfaces;
    struct bpf2socks_network_runtime *networks;
};

int bpf2socks_udp6_recovery_start(struct bpf2socks_bpf_runtime *runtime);
void bpf2socks_udp6_recovery_stop(struct bpf2socks_bpf_runtime *runtime);
void bpf2socks_udp6_recovery_cleanup(void);
int bpf2socks_bpf_object_load_tc_programs(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime,
    bool log_error);

int bpf2socks_interface_policy_start(
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime);
void bpf2socks_interface_policy_stop(struct bpf2socks_bpf_runtime *runtime);
int bpf2socks_network_selection_start(struct bpf2socks_bpf_runtime *runtime);
void bpf2socks_network_selection_stop(struct bpf2socks_bpf_runtime *runtime);

int bpf2socks_bpf_runtime_probe(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    char *message,
    size_t message_size);
int bpf2socks_bpf_runtime_start(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime);
void bpf2socks_bpf_runtime_stop(struct bpf2socks_bpf_runtime *runtime);

#endif
