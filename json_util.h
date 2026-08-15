// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_JSON_UTIL_H
#define BPF2SOCKS_JSON_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char *bpf2socks_json_read_file(const char *path);

const char *bpf2socks_json_object(const char *json, const char *key);

uint32_t bpf2socks_json_uint(
    const char *json,
    const char *key,
    uint32_t fallback);

bool bpf2socks_json_bool(
    const char *json,
    const char *key,
    bool fallback);

bool bpf2socks_json_string(
    const char *json,
    const char *key,
    char *out,
    size_t out_size);

void bpf2socks_json_uint_array(
    const char *json,
    const char *key,
    uint32_t *out,
    size_t *count,
    size_t max_count);

bool bpf2socks_json_string_array(
    const char *json,
    const char *key,
    char *out,
    size_t row_size,
    size_t *count,
    size_t max_count);

void bpf2socks_json_print_string(const char *value);

#endif
