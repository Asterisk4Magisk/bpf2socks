// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#ifndef ASTERISK_BPF2SOCKS_TCP_ACTIVE_LIST_H
#define ASTERISK_BPF2SOCKS_TCP_ACTIVE_LIST_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Generate a type-safe intrusive doubly-linked list for a type containing:
 *
 *     bool active_linked;
 *     TYPE *active_prev;
 *     TYPE *active_next;
 *
 * Removal performs a fixed number of pointer updates and never scans the list.
 */
#define BPF2SOCKS_DEFINE_TCP_ACTIVE_LIST(prefix, type)                                      \
    static inline void prefix##_add(type **head, type *node) {                              \
        if (head == NULL || node == NULL || node->active_linked) return;                    \
        node->active_prev = NULL;                                                           \
        node->active_next = *head;                                                          \
        if (*head != NULL) (*head)->active_prev = node;                                     \
        *head = node;                                                                       \
        node->active_linked = true;                                                         \
    }                                                                                      \
    static inline bool prefix##_remove(type **head, type *node) {                           \
        if (head == NULL || node == NULL || !node->active_linked) return false;             \
        if (node->active_prev != NULL) {                                                    \
            node->active_prev->active_next = node->active_next;                             \
        } else {                                                                           \
            *head = node->active_next;                                                      \
        }                                                                                  \
        if (node->active_next != NULL) node->active_next->active_prev = node->active_prev;  \
        node->active_prev = NULL;                                                           \
        node->active_next = NULL;                                                           \
        node->active_linked = false;                                                        \
        return true;                                                                       \
    }

#endif
