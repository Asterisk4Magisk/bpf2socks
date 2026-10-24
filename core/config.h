// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_CONFIG_H
#define BPF2SOCKS_CORE_CONFIG_H

#include "bpf2socks.h"

#include <stdbool.h>

/* Built-in defaults: global mode, the default token prefixes, this process's group bypassed. */
void bpf2socks_config_defaults(
    struct bpf2socks_runtime_config *config,
    struct bpf2socks_policy_config *policy);

/*
 * Reads the JSON config at path over the defaults and clamps every tunable.
 * An absent optional field keeps its default; a malformed or out-of-range one
 * is logged and fails the load (-1).
 */
int bpf2socks_config_load(
    const char *path,
    bool dns_enhancement,
    struct bpf2socks_runtime_config *config,
    struct bpf2socks_policy_config *policy);

#endif
