// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef BPF2SOCKS_CORE_JSON_H
#define BPF2SOCKS_CORE_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

char *bpf2socks_json_read_file(const char *path);

const char *bpf2socks_json_object(const char *json, const char *key);

bool bpf2socks_json_has_key(const char *json, const char *key);

/* Leaves value unchanged when key is absent; false for a non-integer or a value above max_value. */
bool bpf2socks_json_uint_field(
    const char *json,
    const char *key,
    uint32_t max_value,
    uint32_t *value);

bool bpf2socks_json_bool(
    const char *json,
    const char *key,
    bool fallback);

/* False when key is absent, the value is not a string, or it does not fit out. */
bool bpf2socks_json_string(
    const char *json,
    const char *key,
    char *out,
    size_t out_size);

/* True for an absent key; false for a malformed array or more than max_count entries. */
bool bpf2socks_json_uint_array(
    const char *json,
    const char *key,
    uint32_t *out,
    size_t *count,
    size_t max_count);

/* True for an absent key; false for a malformed array, too many entries, or an entry that does not fit row_size. */
bool bpf2socks_json_string_array(
    const char *json,
    const char *key,
    char *out,
    size_t row_size,
    size_t *count,
    size_t max_count);

void bpf2socks_json_print_string(const char *value);

#endif
