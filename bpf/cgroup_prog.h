// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BPF_CGROUP_PROG_H
#define BPF2SOCKS_BPF_CGROUP_PROG_H

#include "bpf/runtime.h"
#include "bpf2socks.h"

#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Generators of the cgroup sock_addr programs. Each returns a loaded program
 * fd, or -1; the maps the program references come from the runtime.
 */


/* bpf/cgroup_prog.c */
size_t bpf2socks_cgroup_prog_inline_bypass_uid_count(const struct bpf2socks_policy_config *policy);
int bpf2socks_cgroup_prog_build4(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error);
int bpf2socks_cgroup_prog_build6(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error);
int bpf2socks_cgroup_prog_build_mapped6(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error);
int bpf2socks_cgroup_prog_build_reverse4(
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    int tcp_peer_map_fd,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error);
int bpf2socks_cgroup_prog_build_reverse6(
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    int tcp_peer_map_fd,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error);
int bpf2socks_cgroup_prog_load_noop(enum bpf_attach_type attach_type, const char *name);
int bpf2socks_cgroup_prog_load_constant(
    enum bpf_prog_type program_type,
    enum bpf_attach_type attach_type,
    int result,
    const char *name);

#endif
