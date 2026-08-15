// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"

#include <string.h>

#define BPF2SOCKS_MAX_INTERFACE_SELECTOR_LENGTH 15U

static size_t interface_selector_bounded_length(const char *text) {
    size_t length = 0U;
    while (length < BPF2SOCKS_MAX_INTERFACE_NAME_LEN && text[length] != '\0') ++length;
    return length;
}

static bool interface_selector_character_valid(unsigned char byte) {
    return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') || byte == '_' || byte == '.' || byte == '-';
}

bool bpf2socks_interface_selector_valid(const char *selector) {
    if (selector == NULL) return false;
    size_t length = interface_selector_bounded_length(selector);
    if (length == 0U || length > BPF2SOCKS_MAX_INTERFACE_SELECTOR_LENGTH ||
        length >= BPF2SOCKS_MAX_INTERFACE_NAME_LEN) return false;
    size_t ordinary_length = selector[length - 1U] == '+' ? length - 1U : length;
    if (ordinary_length == 0U) return false;
    for (size_t index = 0U; index < ordinary_length; ++index) {
        if (!interface_selector_character_valid((unsigned char)selector[index])) return false;
    }
    return true;
}

bool bpf2socks_interface_matches_selector(const char *name, const char *selector) {
    if (name == NULL || selector == NULL) return false;
    size_t length = interface_selector_bounded_length(selector);
    if (length == 0U || length >= BPF2SOCKS_MAX_INTERFACE_NAME_LEN) return false;
    return selector[length - 1U] == '+' ?
        length > 1U && strncmp(name, selector, length - 1U) == 0 : strcmp(name, selector) == 0;
}
