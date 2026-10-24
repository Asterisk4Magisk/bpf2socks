// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_BPF_POLICY_H
#define BPF2SOCKS_BPF_POLICY_H

#include "bpf2socks.h"

#include <stdbool.h>
#include <stddef.h>

int bpf2socks_policy_load_uids(int uid_map_fd, const struct bpf2socks_policy_config *policy);
int bpf2socks_policy_load_cidr_file(int map_fd, const char *path, int expected_family);
int bpf2socks_policy_load_cidr_list(int map_fd, const char cidrs[][BPF2SOCKS_MAX_CIDR_TEXT_LEN], size_t count, int expected_family);

bool bpf2socks_interface_selector_valid(const char *selector);
bool bpf2socks_interface_matches_selector(const char *name, const char *selector);

#endif
