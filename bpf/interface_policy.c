// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/policy.h"
#include "bpf/runtime.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "core/log.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/*
 * Network changes arrive as bursts of netlink messages. After the first one,
 * keep reading until the socket stays quiet for this long, bounded by the
 * window, and refresh the maps once for the whole burst.
 */
#define BPF2SOCKS_INTERFACE_QUIET_MILLISECONDS 20
#define BPF2SOCKS_INTERFACE_BATCH_WINDOW_MILLISECONDS 100

/* A growable set of fixed-size map keys. */
struct key_set {
    uint8_t *keys;
    size_t key_size;
    size_t count;
    size_t capacity;
};

struct bpf2socks_interface_runtime {
    pthread_t thread;
    int netlink_fd;
    int stop_fd;
    _Atomic bool stop_requested;
    const struct bpf2socks_policy_config *policy;
    struct bpf2socks_bpf_runtime *bpf_runtime;
    /* Ignored ifindices as last written to the map; read only by the policy thread. */
    struct key_set ignored_ifindices;
};

/* Work collected from one burst of netlink messages. */
struct interface_policy_changes {
    bool links;
    bool routes;
};

static int open_route_netlink(uint32_t groups) {
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

static bool nlmsg_ok_policy(const struct nlmsghdr *nh, int remaining) {
    return remaining >= (int)sizeof(struct nlmsghdr) &&
        nh->nlmsg_len >= sizeof(struct nlmsghdr) &&
        (int)nh->nlmsg_len <= remaining;
}

static void key_set_init(struct key_set *set, size_t key_size) {
    memset(set, 0, sizeof(*set));
    set->key_size = key_size;
}

static void key_set_free(struct key_set *set) {
    free(set->keys);
    set->keys = NULL;
    set->count = 0U;
    set->capacity = 0U;
}

static bool key_set_contains(const struct key_set *set, const void *key) {
    for (size_t index = 0U; index < set->count; ++index) {
        if (memcmp(set->keys + index * set->key_size, key, set->key_size) == 0) return true;
    }
    return false;
}

static int key_set_add(struct key_set *set, const void *key) {
    if (key_set_contains(set, key)) return 0;
    if (set->count == set->capacity) {
        size_t capacity = set->capacity == 0U ? 16U : set->capacity * 2U;
        uint8_t *keys = realloc(set->keys, capacity * set->key_size);
        if (keys == NULL) return -1;
        set->keys = keys;
        set->capacity = capacity;
    }
    memcpy(set->keys + set->count * set->key_size, key, set->key_size);
    ++set->count;
    return 0;
}

/*
 * Makes the map hold exactly the desired keys. Missing keys are written before
 * stale ones are removed, so a lookup never sees a transiently emptied map.
 */
static int sync_map_keys(int map_fd, const struct key_set *desired) {
    uint8_t value = 1U;
    for (size_t index = 0U; index < desired->count; ++index) {
        if (bpf2socks_bpf_map_update(map_fd, desired->keys + index * desired->key_size, &value) < 0) return -1;
    }

    struct key_set stale;
    key_set_init(&stale, desired->key_size);
    uint8_t key[sizeof(struct bpf2socks_lpm6_key)];
    uint8_t next[sizeof(struct bpf2socks_lpm6_key)];
    if (desired->key_size > sizeof(key)) {
        errno = EINVAL;
        return -1;
    }
    const void *cursor = NULL;
    int result = 0;
    while (bpf2socks_bpf_map_next_key(map_fd, cursor, next) == 0) {
        if (!key_set_contains(desired, next) && key_set_add(&stale, next) < 0) {
            result = -1;
            break;
        }
        memcpy(key, next, desired->key_size);
        cursor = key;
    }
    for (size_t index = 0U; result == 0 && index < stale.count; ++index) {
        if (bpf2socks_bpf_map_delete(map_fd, stale.keys + index * stale.key_size) < 0 && errno != ENOENT) {
            result = -1;
        }
    }
    int saved = errno;
    key_set_free(&stale);
    errno = saved;
    return result;
}

static bool interface_name_ignored(const struct bpf2socks_interface_runtime *interfaces, const char *name) {
    for (size_t selector_index = 0U;
         selector_index < interfaces->policy->ignored_interface_count &&
         selector_index < BPF2SOCKS_MAX_INTERFACES;
         ++selector_index) {
        if (bpf2socks_interface_matches_selector(name, interfaces->policy->ignored_interfaces[selector_index])) {
            return true;
        }
    }
    return false;
}

static bool ifindex_ignored(const struct bpf2socks_interface_runtime *interfaces, int ifindex) {
    if (ifindex <= 0) return false;
    uint32_t key = (uint32_t)ifindex;
    return key_set_contains(&interfaces->ignored_ifindices, &key);
}

static int refresh_ignored_ifindices(struct bpf2socks_interface_runtime *interfaces) {
    struct if_nameindex *system_interfaces = if_nameindex();
    if (system_interfaces == NULL) return -1;

    struct key_set desired;
    key_set_init(&desired, sizeof(uint32_t));
    int result = 0;
    for (const struct if_nameindex *entry = system_interfaces;
         entry->if_index != 0U && entry->if_name != NULL;
         ++entry) {
        if (!interface_name_ignored(interfaces, entry->if_name)) continue;
        uint32_t key = entry->if_index;
        if (key_set_add(&desired, &key) < 0) {
            result = -1;
            break;
        }
    }
    if_freenameindex(system_interfaces);
    if (result == 0) result = sync_map_keys(interfaces->bpf_runtime->ignored_ifindex_map_fd, &desired);
    if (result < 0) {
        int saved = errno;
        key_set_free(&desired);
        errno = saved;
        return -1;
    }
    key_set_free(&interfaces->ignored_ifindices);
    interfaces->ignored_ifindices = desired;
    return 0;
}

static uint32_t mask_ipv4_route_addr(uint32_t addr, uint8_t prefixlen) {
    if (prefixlen == 0U) return 0U;
    if (prefixlen >= 32U) return addr;
    uint32_t mask = 0xffffffffU << (32U - prefixlen);
    return htonl(ntohl(addr) & mask);
}

static void mask_ipv6_route_addr(uint8_t addr[16], uint8_t prefixlen) {
    if (prefixlen >= 128U) return;
    size_t full_bytes = (size_t)(prefixlen / 8U);
    uint8_t rest_bits = (uint8_t)(prefixlen % 8U);
    if (full_bytes >= 16U) return;
    if (rest_bits == 0U) {
        memset(addr + full_bytes, 0, 16U - full_bytes);
        return;
    }
    addr[full_bytes] &= (uint8_t)(0xffU << (8U - rest_bits));
    memset(addr + full_bytes + 1U, 0, 16U - full_bytes - 1U);
}

static int route_output_ifindex(const struct nlmsghdr *nh) {
    const struct rtmsg *rtm = (const struct rtmsg *)NLMSG_DATA(nh);
    int len = RTM_PAYLOAD(nh);
    int oif = 0;
    for (const struct rtattr *attr = RTM_RTA(rtm); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == RTA_OIF && RTA_PAYLOAD(attr) >= (int)sizeof(oif)) {
            memcpy(&oif, RTA_DATA(attr), sizeof(oif));
        }
    }
    return oif;
}

static int collect_ignored_route(
    const struct bpf2socks_interface_runtime *interfaces,
    const struct nlmsghdr *nh,
    struct key_set *routes) {
    const struct rtmsg *rtm = (const struct rtmsg *)NLMSG_DATA(nh);
    if (rtm->rtm_type != RTN_UNICAST) {
        return 0;
    }
    if (rtm->rtm_family == AF_INET && rtm->rtm_dst_len > 32U) return 0;
    if (rtm->rtm_family == AF_INET6 && rtm->rtm_dst_len > 128U) return 0;
    if (rtm->rtm_family != AF_INET && rtm->rtm_family != AF_INET6) return 0;

    int len = RTM_PAYLOAD(nh);
    const struct rtattr *attr = RTM_RTA(rtm);
    int oif = 0;
    uint32_t dst = 0U;
    uint8_t dst6[16];
    memset(dst6, 0, sizeof(dst6));
    for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == RTA_OIF && RTA_PAYLOAD(attr) >= (int)sizeof(oif)) {
            memcpy(&oif, RTA_DATA(attr), sizeof(oif));
        } else if (attr->rta_type == RTA_DST && RTA_PAYLOAD(attr) >= (int)sizeof(dst)) {
            if (rtm->rtm_family == AF_INET) {
                memcpy(&dst, RTA_DATA(attr), sizeof(dst));
            } else if (RTA_PAYLOAD(attr) >= (int)sizeof(dst6)) {
                memcpy(dst6, RTA_DATA(attr), sizeof(dst6));
            }
        }
    }

    if (!ifindex_ignored(interfaces, oif)) return 0;

    if (rtm->rtm_family == AF_INET) {
        struct bpf2socks_lpm4_key key;
        memset(&key, 0, sizeof(key));
        key.prefixlen = rtm->rtm_dst_len;
        key.addr = mask_ipv4_route_addr(dst, rtm->rtm_dst_len);
        return key_set_add(routes, &key);
    }
    struct bpf2socks_lpm6_key key;
    memset(&key, 0, sizeof(key));
    key.prefixlen = rtm->rtm_dst_len;
    memcpy(key.addr, dst6, sizeof(key.addr));
    mask_ipv6_route_addr(key.addr, rtm->rtm_dst_len);
    return key_set_add(routes, &key);
}

static int dump_ignored_routes_family(
    const struct bpf2socks_interface_runtime *interfaces,
    int family,
    struct key_set *routes) {
    int fd = open_route_netlink(0U);
    if (fd < 0) return -1;

    struct {
        struct nlmsghdr nh;
        struct rtmsg rt;
    } req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.rt));
    req.nh.nlmsg_type = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1U;
    req.rt.rtm_family = (uint8_t)family;

    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    if (sendto(fd, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    int result = 0;
    char buf[16384];
    while (result == 0) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0 && errno == EINTR) continue;
        if (len <= 0) {
            result = -1;
            if (len == 0) errno = ECONNRESET;
            break;
        }
        int remaining = (int)len;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; nlmsg_ok_policy(nh, remaining); nh = NLMSG_NEXT(nh, remaining)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                close(fd);
                return 0;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
                errno = err->error < 0 ? -err->error : EIO;
                result = -1;
                break;
            }
            if (nh->nlmsg_type == RTM_NEWROUTE && collect_ignored_route(interfaces, nh, routes) < 0) {
                result = -1;
                break;
            }
        }
    }

    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}

static int sync_ignored_routes_family(
    const struct bpf2socks_interface_runtime *interfaces,
    int family,
    int map_fd,
    size_t key_size) {
    if (map_fd < 0) return 0;
    struct key_set routes;
    key_set_init(&routes, key_size);
    int result = dump_ignored_routes_family(interfaces, family, &routes);
    if (result == 0) result = sync_map_keys(map_fd, &routes);
    int saved = errno;
    key_set_free(&routes);
    errno = saved;
    return result;
}

static int dump_ignored_routes(const struct bpf2socks_interface_runtime *interfaces) {
    if (sync_ignored_routes_family(
            interfaces,
            AF_INET,
            interfaces->bpf_runtime->ignored_route_cidr4_map_fd,
            sizeof(struct bpf2socks_lpm4_key)) < 0) {
        return -1;
    }
    return sync_ignored_routes_family(
        interfaces,
        AF_INET6,
        interfaces->bpf_runtime->ignored_route_cidr6_map_fd,
        sizeof(struct bpf2socks_lpm6_key));
}

static int refresh_interface_policy(struct bpf2socks_interface_runtime *interfaces) {
    if (refresh_ignored_ifindices(interfaces) < 0) return -1;
    return dump_ignored_routes(interfaces);
}

static const char *link_message_name(const struct nlmsghdr *nh) {
    const struct ifinfomsg *ifi = (const struct ifinfomsg *)NLMSG_DATA(nh);
    int len = (int)nh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(*ifi));
    for (const struct rtattr *attr = IFLA_RTA(ifi); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        if (attr->rta_type == IFLA_IFNAME && RTA_PAYLOAD(attr) > 0 &&
            memchr(RTA_DATA(attr), '\0', RTA_PAYLOAD(attr)) != NULL) {
            return (const char *)RTA_DATA(attr);
        }
    }
    return NULL;
}

/*
 * Only events that can change the ignored sets count: links that match a
 * selector or are currently ignored, and routes through an ignored interface.
 */
static void note_interface_policy_message(
    const struct bpf2socks_interface_runtime *interfaces,
    const struct nlmsghdr *nh,
    struct interface_policy_changes *changes) {
    if (nh->nlmsg_type == RTM_NEWLINK || nh->nlmsg_type == RTM_DELLINK) {
        if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) return;
        const struct ifinfomsg *ifi = (const struct ifinfomsg *)NLMSG_DATA(nh);
        const char *name = link_message_name(nh);
        if (ifindex_ignored(interfaces, ifi->ifi_index) ||
            (name != NULL && interface_name_ignored(interfaces, name))) {
            changes->links = true;
        }
    } else if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
        if (nh->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg))) return;
        if (ifindex_ignored(interfaces, route_output_ifindex(nh))) changes->routes = true;
    }
}

/*
 * Reads every queued netlink message. Returns 1 when the stop event fired,
 * -1 on a fatal socket error and 0 otherwise. A receive-buffer overflow
 * (ENOBUFS) loses events, so it forces a full refresh.
 */
static int drain_interface_policy_messages(
    const struct bpf2socks_interface_runtime *interfaces,
    struct interface_policy_changes *changes) {
    char buf[8192];
    for (;;) {
        ssize_t len = recv(interfaces->netlink_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len < 0 && errno == EINTR) continue;
        if (len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (len < 0 && errno == ENOBUFS) {
            changes->links = true;
            changes->routes = true;
            continue;
        }
        if (len <= 0) return -1;
        int remaining = (int)len;
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; nlmsg_ok_policy(nh, remaining); nh = NLMSG_NEXT(nh, remaining)) {
            if (nh->nlmsg_type == NLMSG_DONE) break;
            if (nh->nlmsg_type == NLMSG_ERROR) continue;
            note_interface_policy_message(interfaces, nh, changes);
        }
    }
}

/* Waits for netlink input or stop: 1 readable, 0 timeout, -1 stop or error. */
static int wait_interface_policy_input(const struct bpf2socks_interface_runtime *interfaces, int timeout_ms) {
    for (;;) {
        struct pollfd pfds[2] = {
            {
                .fd = interfaces->netlink_fd,
                .events = POLLIN,
            },
            {
                .fd = interfaces->stop_fd,
                .events = POLLIN,
            },
        };
        int ready = poll(pfds, 2U, timeout_ms);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (ready == 0) return 0;
        if ((pfds[1].revents & POLLIN) != 0) return -1;
        if ((pfds[0].revents & (POLLIN | POLLERR)) != 0) return 1;
        return -1;
    }
}

static void apply_interface_policy_changes(
    struct bpf2socks_interface_runtime *interfaces,
    const struct interface_policy_changes *changes) {
    if (changes->links) {
        if (refresh_interface_policy(interfaces) < 0) {
            bpf2socks_log("failed to refresh ignored interface policy: errno=%d", errno);
        }
    } else if (changes->routes) {
        if (dump_ignored_routes(interfaces) < 0) {
            bpf2socks_log("failed to refresh ignored interface routes: errno=%d", errno);
        }
    }
}

static void *interface_policy_thread(void *arg) {
    struct bpf2socks_interface_runtime *interfaces = arg;
    while (!atomic_load_explicit(&interfaces->stop_requested, memory_order_acquire)) {
        if (wait_interface_policy_input(interfaces, -1) <= 0) break;
        struct interface_policy_changes changes = {0};
        if (drain_interface_policy_messages(interfaces, &changes) < 0) break;
        uint64_t batch_end_ms = bpf2socks_now_ms() + BPF2SOCKS_INTERFACE_BATCH_WINDOW_MILLISECONDS;
        bool stopping = false;
        for (;;) {
            uint64_t now_ms = bpf2socks_now_ms();
            if (now_ms >= batch_end_ms) break;
            uint64_t remaining_ms = batch_end_ms - now_ms;
            int quiet_ms = remaining_ms < BPF2SOCKS_INTERFACE_QUIET_MILLISECONDS
                ? (int)remaining_ms
                : BPF2SOCKS_INTERFACE_QUIET_MILLISECONDS;
            int waited = wait_interface_policy_input(interfaces, quiet_ms);
            if (waited == 0) break;
            if (waited < 0 || drain_interface_policy_messages(interfaces, &changes) < 0) {
                stopping = true;
                break;
            }
        }
        if (stopping) break;
        apply_interface_policy_changes(interfaces, &changes);
    }
    return NULL;
}

int bpf2socks_interface_policy_start(
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime) {
    if (policy == NULL || runtime == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (policy->ignored_interface_count == 0U) return 0;
    if (runtime->ignored_ifindex_map_fd < 0 ||
        runtime->ignored_route_cidr4_map_fd < 0 ||
        (policy->enable_ipv6 && runtime->ignored_route_cidr6_map_fd < 0)) {
        errno = EBADF;
        return -1;
    }

    struct bpf2socks_interface_runtime *interfaces = calloc(1U, sizeof(*interfaces));
    if (interfaces == NULL) return -1;
    interfaces->netlink_fd = -1;
    interfaces->stop_fd = -1;
    atomic_init(&interfaces->stop_requested, false);
    interfaces->policy = policy;
    interfaces->bpf_runtime = runtime;
    key_set_init(&interfaces->ignored_ifindices, sizeof(uint32_t));

    interfaces->netlink_fd = open_route_netlink(RTMGRP_LINK | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE);
    if (interfaces->netlink_fd < 0) {
        int saved = errno;
        free(interfaces);
        errno = saved;
        return -1;
    }

    interfaces->stop_fd = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
    if (interfaces->stop_fd < 0) {
        int saved = errno;
        close(interfaces->netlink_fd);
        free(interfaces);
        errno = saved;
        return -1;
    }

    if (refresh_interface_policy(interfaces) < 0) {
        int saved = errno;
        close(interfaces->stop_fd);
        close(interfaces->netlink_fd);
        key_set_free(&interfaces->ignored_ifindices);
        free(interfaces);
        errno = saved;
        return -1;
    }

    int thread_result = pthread_create(&interfaces->thread, NULL, interface_policy_thread, interfaces);
    if (thread_result != 0) {
        close(interfaces->stop_fd);
        close(interfaces->netlink_fd);
        key_set_free(&interfaces->ignored_ifindices);
        free(interfaces);
        errno = thread_result;
        return -1;
    }

    runtime->interfaces = interfaces;
    return 0;
}

void bpf2socks_interface_policy_stop(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime == NULL || runtime->interfaces == NULL) return;
    struct bpf2socks_interface_runtime *interfaces = runtime->interfaces;
    runtime->interfaces = NULL;

    atomic_store_explicit(&interfaces->stop_requested, true, memory_order_release);
    uint64_t signal = 1U;
    ssize_t written;
    do {
        written = write(interfaces->stop_fd, &signal, sizeof(signal));
    } while (written < 0 && errno == EINTR);
    (void)pthread_join(interfaces->thread, NULL);
    if (interfaces->stop_fd >= 0) close(interfaces->stop_fd);
    if (interfaces->netlink_fd >= 0) close(interfaces->netlink_fd);
    key_set_free(&interfaces->ignored_ifindices);
    free(interfaces);
}
