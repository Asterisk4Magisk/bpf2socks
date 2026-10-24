// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BPF_SYSCALL_H
#define BPF2SOCKS_BPF_SYSCALL_H

#include <linux/bpf.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

int bpf2socks_bpf_map_create(enum bpf_map_type type, uint32_t key_size, uint32_t value_size, uint32_t max_entries, uint32_t flags);
int bpf2socks_bpf_map_update(int map_fd, const void *key, const void *value);
int bpf2socks_bpf_map_lookup(int map_fd, const void *key, void *value);
int bpf2socks_bpf_map_next_key(int map_fd, const void *key, void *next_key);
int bpf2socks_bpf_prog_load(
    const struct bpf_insn *insns,
    size_t insn_count,
    const char *name,
    enum bpf_prog_type prog_type,
    enum bpf_attach_type expected_attach_type,
    bool log_error);
int bpf2socks_bpf_prog_attach(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type);
int bpf2socks_bpf_prog_detach(int cgroup_fd, int prog_fd, enum bpf_attach_type attach_type);
int bpf2socks_bpf_cgroup_restore(int cgroup_fd);
int bpf2socks_bpf_map_delete(int map_fd, const void *key);
int bpf2socks_bpf_map_lookup_and_delete(int map_fd, const void *key, void *value);
int bpf2socks_bpf_obj_pin(int fd, const char *path);

#endif
