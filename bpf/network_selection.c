// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/runtime.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "core/log.h"

#include <errno.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Android selects a network per socket with a fwmark: the low 16 bits carry
 * the netId and BPF2SOCKS_FWMARK_EXPLICIT marks a socket the app bound to that
 * network (Network.bindSocket, bindProcessToNetwork). The policy routing rules
 * tell which netIds are default networks:
 *   fwmark 0x0/0xffff [uidrange] lookup <table>        default network (global or per app)
 *   fwmark 0x1NNNN/0x1ffff lookup <table>              explicitly selected netId 0xNNNN
 * A netId whose explicit rule shares a table with a default rule is a default
 * network. The BPF hooks bypass a socket explicitly bound to any other netId,
 * so it reaches the network the app chose instead of the proxy's.
 */
#define BPF2SOCKS_FWMARK_NETID_MASK 0xffffU
#define BPF2SOCKS_FWMARK_EXPLICIT_MASK 0x1ffffU
#define BPF2SOCKS_NETWORK_RULE_SETTLE_MILLISECONDS 100
#define BPF2SOCKS_MAX_RULE_TABLES 256U

struct bpf2socks_network_runtime {
    pthread_t thread;
    int netlink_fd;
    int stop_fd;
    int map_fd;
    _Atomic bool stop_requested;
};

struct network_rules {
    uint32_t default_tables[BPF2SOCKS_MAX_RULE_TABLES];
    size_t default_table_count;
    uint32_t explicit_netids[BPF2SOCKS_MAX_RULE_TABLES];
    uint32_t explicit_tables[BPF2SOCKS_MAX_RULE_TABLES];
    size_t explicit_count;
};

static int open_rule_netlink(uint32_t groups) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;
    struct sockaddr_nl local;
    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = groups;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

static void note_rule(const struct nlmsghdr *nh, struct network_rules *rules) {
    if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct fib_rule_hdr))) return;
    const struct fib_rule_hdr *hdr = (const struct fib_rule_hdr *)NLMSG_DATA(nh);
    if (hdr->action != FR_ACT_TO_TBL) return;
    uint32_t table = hdr->table;
    /* The kernel omits FRA_FWMARK when the mark is zero; the mask tells a fwmark rule. */
    uint32_t mark = 0U;
    uint32_t mask = 0U;
    bool has_mask = false;
    int len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*hdr));
    for (const struct rtattr *attr = (const struct rtattr *)((const uint8_t *)hdr + NLMSG_ALIGN(sizeof(*hdr)));
         RTA_OK(attr, len);
         attr = RTA_NEXT(attr, len)) {
        if (RTA_PAYLOAD(attr) < sizeof(uint32_t)) continue;
        uint32_t value;
        memcpy(&value, RTA_DATA(attr), sizeof(value));
        if (attr->rta_type == FRA_TABLE) table = value;
        if (attr->rta_type == FRA_FWMARK) mark = value;
        if (attr->rta_type == FRA_FWMASK) {
            mask = value;
            has_mask = true;
        }
    }
    if (!has_mask) return;
    if (mark == 0U && mask == BPF2SOCKS_FWMARK_NETID_MASK) {
        if (rules->default_table_count < BPF2SOCKS_MAX_RULE_TABLES) {
            rules->default_tables[rules->default_table_count++] = table;
        }
    } else if (mask == BPF2SOCKS_FWMARK_EXPLICIT_MASK && (mark & BPF2SOCKS_FWMARK_EXPLICIT) != 0U &&
        (mark & BPF2SOCKS_FWMARK_NETID_MASK) != 0U) {
        if (rules->explicit_count < BPF2SOCKS_MAX_RULE_TABLES) {
            rules->explicit_netids[rules->explicit_count] = mark & BPF2SOCKS_FWMARK_NETID_MASK;
            rules->explicit_tables[rules->explicit_count] = table;
            ++rules->explicit_count;
        }
    }
}

static int dump_rules(struct network_rules *rules) {
    int fd = open_rule_netlink(0U);
    if (fd < 0) return -1;
    struct {
        struct nlmsghdr nh;
        struct fib_rule_hdr rule;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rule));
    req.nh.nlmsg_type = RTM_GETRULE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1U;
    req.rule.family = AF_INET;
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    char buf[16384];
    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0 && errno == EINTR) continue;
        if (len <= 0) {
            int saved = len == 0 ? ECONNRESET : errno;
            close(fd);
            errno = saved;
            return -1;
        }
        int remaining = (int)len;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf;
             remaining >= (int)sizeof(struct nlmsghdr) && nh->nlmsg_len >= sizeof(struct nlmsghdr) &&
                 (int)nh->nlmsg_len <= remaining;
             nh = NLMSG_NEXT(nh, remaining)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return 0;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
                close(fd);
                errno = err->error < 0 ? -err->error : EIO;
                return -1;
            }
            if (nh->nlmsg_type == RTM_NEWRULE) note_rule(nh, rules);
        }
    }
}

static bool rules_mark_default(const struct network_rules *rules, uint32_t table) {
    for (size_t index = 0U; index < rules->default_table_count; ++index) {
        if (rules->default_tables[index] == table) return true;
    }
    return false;
}

static bool netid_is_default(const struct network_rules *rules, uint32_t netid) {
    for (size_t index = 0U; index < rules->explicit_count; ++index) {
        if (rules->explicit_netids[index] == netid && rules_mark_default(rules, rules->explicit_tables[index])) {
            return true;
        }
    }
    return false;
}

/*
 * Writes the default netIds, removes stale ones, then (re)publishes the ready
 * key. Without a usable rule set the ready key is removed, which keeps every
 * explicitly bound socket on the proxy rather than guessing.
 */
static int refresh_default_networks(int map_fd) {
    struct network_rules rules;
    memset(&rules, 0, sizeof(rules));
    uint32_t ready_key = BPF2SOCKS_DEFAULT_NETWORK_READY_KEY;
    uint8_t present = 1U;
    int dumped = dump_rules(&rules);
    if (dumped < 0 || rules.default_table_count == 0U) {
        int saved = dumped < 0 ? errno : ENOENT;
        (void)bpf2socks_bpf_map_delete(map_fd, &ready_key);
        errno = saved;
        return -1;
    }
    for (size_t index = 0U; index < rules.explicit_count; ++index) {
        uint32_t netid = rules.explicit_netids[index];
        if (netid_is_default(&rules, netid) && bpf2socks_bpf_map_update(map_fd, &netid, &present) < 0) return -1;
    }
    uint32_t key;
    uint32_t next;
    const void *cursor = NULL;
    uint32_t stale[BPF2SOCKS_MAX_RULE_TABLES];
    size_t stale_count = 0U;
    while (bpf2socks_bpf_map_next_key(map_fd, cursor, &next) == 0) {
        if (next != ready_key && !netid_is_default(&rules, next) && stale_count < BPF2SOCKS_MAX_RULE_TABLES) {
            stale[stale_count++] = next;
        }
        key = next;
        cursor = &key;
    }
    for (size_t index = 0U; index < stale_count; ++index) (void)bpf2socks_bpf_map_delete(map_fd, &stale[index]);
    return bpf2socks_bpf_map_update(map_fd, &ready_key, &present);
}

static bool drain_rule_messages(int fd) {
    char buf[8192];
    bool changed = false;
    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len < 0 && errno == EINTR) continue;
        if (len < 0 && errno == ENOBUFS) {
            changed = true;
            continue;
        }
        if (len <= 0) return changed;
        changed = true;
    }
}

static void *network_selection_thread(void *arg) {
    struct bpf2socks_network_runtime *networks = arg;
    while (!atomic_load_explicit(&networks->stop_requested, memory_order_acquire)) {
        struct pollfd pfds[2] = {
            {.fd = networks->netlink_fd, .events = POLLIN},
            {.fd = networks->stop_fd, .events = POLLIN},
        };
        int ready = poll(pfds, 2U, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || (pfds[1].revents & POLLIN) != 0) break;
        if (!drain_rule_messages(networks->netlink_fd)) continue;
        /* A network switch rewrites many rules: let the burst settle first. */
        struct pollfd stop = {.fd = networks->stop_fd, .events = POLLIN};
        if (poll(&stop, 1U, BPF2SOCKS_NETWORK_RULE_SETTLE_MILLISECONDS) > 0) break;
        (void)drain_rule_messages(networks->netlink_fd);
        if (refresh_default_networks(networks->map_fd) < 0) {
            bpf2socks_log("default network refresh failed; explicitly bound sockets stay proxied: errno=%d", errno);
        }
    }
    return NULL;
}

int bpf2socks_network_selection_start(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime == NULL || runtime->default_network_map_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct bpf2socks_network_runtime *networks = calloc(1U, sizeof(*networks));
    if (networks == NULL) return -1;
    networks->map_fd = runtime->default_network_map_fd;
    atomic_init(&networks->stop_requested, false);
    networks->netlink_fd = open_rule_netlink(RTMGRP_IPV4_RULE);
    networks->stop_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (networks->netlink_fd < 0 || networks->stop_fd < 0) {
        int saved = errno;
        if (networks->netlink_fd >= 0) close(networks->netlink_fd);
        if (networks->stop_fd >= 0) close(networks->stop_fd);
        free(networks);
        errno = saved;
        return -1;
    }
    if (refresh_default_networks(networks->map_fd) < 0) {
        bpf2socks_log("default networks unknown; explicitly bound sockets stay proxied: errno=%d", errno);
    }
    int thread_result = pthread_create(&networks->thread, NULL, network_selection_thread, networks);
    if (thread_result != 0) {
        close(networks->netlink_fd);
        close(networks->stop_fd);
        free(networks);
        errno = thread_result;
        return -1;
    }
    runtime->networks = networks;
    return 0;
}

void bpf2socks_network_selection_stop(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime == NULL || runtime->networks == NULL) return;
    struct bpf2socks_network_runtime *networks = runtime->networks;
    runtime->networks = NULL;
    atomic_store_explicit(&networks->stop_requested, true, memory_order_release);
    uint64_t signal = 1U;
    ssize_t written;
    do {
        written = write(networks->stop_fd, &signal, sizeof(signal));
    } while (written < 0 && errno == EINTR);
    (void)pthread_join(networks->thread, NULL);
    close(networks->stop_fd);
    close(networks->netlink_fd);
    free(networks);
}
