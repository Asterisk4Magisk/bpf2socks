// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "json_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *bpf2socks_json_read_file(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length < 0) {
        fclose(file);
        return NULL;
    }
    rewind(file);
    char *data = calloc((size_t)length + 1U, 1U);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }
    if (length > 0 && fread(data, 1U, (size_t)length, file) != (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    return data;
}

static bool json_whitespace(char value) {
    return value == ' ' || value == '\n' || value == '\t' || value == '\r';
}

static const char *skip_json_whitespace(const char *pos) {
    while (json_whitespace(*pos)) ++pos;
    return pos;
}

static const char *json_value_pos(const char *json, const char *key) {
    char needle[96];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *pos = strstr(json, needle);
    if (pos == NULL) return NULL;
    pos = strchr(pos, ':');
    if (pos == NULL) return NULL;
    return pos + 1;
}

const char *bpf2socks_json_object(const char *json, const char *key) {
    const char *value = json_value_pos(json, key);
    if (value == NULL) return NULL;
    return strchr(value, '{');
}

uint32_t bpf2socks_json_uint(
    const char *json,
    const char *key,
    uint32_t fallback) {
    const char *pos = json_value_pos(json, key);
    if (pos == NULL) return fallback;
    return (uint32_t)strtoul(pos, NULL, 10);
}

bool bpf2socks_json_bool(
    const char *json,
    const char *key,
    bool fallback) {
    const char *pos = json_value_pos(json, key);
    if (pos == NULL) return fallback;
    pos = skip_json_whitespace(pos);
    if (strncmp(pos, "true", 4) == 0) return true;
    if (strncmp(pos, "false", 5) == 0) return false;
    return fallback;
}

bool bpf2socks_json_string(
    const char *json,
    const char *key,
    char *out,
    size_t out_size) {
    if (out_size == 0U) return false;
    const char *pos = json_value_pos(json, key);
    if (pos == NULL) return false;
    pos = strchr(pos, '"');
    if (pos == NULL) return false;
    ++pos;
    const char *end = strchr(pos, '"');
    if (end == NULL) return false;
    size_t length = (size_t)(end - pos);
    if (length >= out_size) length = out_size - 1U;
    memcpy(out, pos, length);
    out[length] = '\0';
    return true;
}

void bpf2socks_json_uint_array(
    const char *json,
    const char *key,
    uint32_t *out,
    size_t *count,
    size_t max_count) {
    *count = 0U;
    const char *pos = json_value_pos(json, key);
    if (pos == NULL) return;
    pos = strchr(pos, '[');
    if (pos == NULL) return;
    ++pos;
    while (*pos != '\0' && *pos != ']' && *count < max_count) {
        while (json_whitespace(*pos) || *pos == ',') ++pos;
        if (*pos == ']') break;
        char *end = NULL;
        unsigned long value = strtoul(pos, &end, 10);
        if (end == pos) break;
        out[(*count)++] = (uint32_t)value;
        pos = end;
    }
}

bool bpf2socks_json_string_array(
    const char *json,
    const char *key,
    char *out,
    size_t row_size,
    size_t *count,
    size_t max_count) {
    if (count == NULL) return false;
    *count = 0U;
    if (json == NULL || key == NULL || out == NULL || row_size == 0U) return false;

    char needle[96];
    int needle_length_result = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (needle_length_result < 0 || (size_t)needle_length_result >= sizeof(needle)) return false;
    size_t needle_length = (size_t)needle_length_result;

    const char *pos = json;
    for (;;) {
        const char *candidate = strstr(pos, needle);
        if (candidate == NULL) return true;
        const char *after_key = skip_json_whitespace(candidate + needle_length);
        if (*after_key == ':') {
            pos = skip_json_whitespace(after_key + 1);
            break;
        }
        pos = candidate + 1;
    }

    if (*pos != '[') return false;
    ++pos;
    pos = skip_json_whitespace(pos);
    if (*pos == ']') return true;

    for (;;) {
        if (*pos == '\0' || *count >= max_count || *pos != '"') return false;
        ++pos;
        const char *end = strchr(pos, '"');
        if (end == NULL) return false;
        size_t length = (size_t)(end - pos);
        if (length >= row_size) length = row_size - 1U;
        char *slot = out + (*count * row_size);
        memcpy(slot, pos, length);
        slot[length] = '\0';
        ++(*count);
        pos = skip_json_whitespace(end + 1);
        if (*pos == ']') return true;
        if (*pos != ',') return false;
        pos = skip_json_whitespace(pos + 1);
        if (*pos == ']') return false;
    }
}

void bpf2socks_json_print_string(const char *value) {
    putchar('"');
    if (value != NULL) {
        for (const char *ptr = value; *ptr != '\0'; ++ptr) {
            if (*ptr == '"' || *ptr == '\\') {
                putchar('\\');
                putchar(*ptr);
            } else if ((unsigned char)*ptr < 0x20U) {
                printf("\\u%04x", (unsigned int)(unsigned char)*ptr);
            } else {
                putchar(*ptr);
            }
        }
    }
    putchar('"');
}
