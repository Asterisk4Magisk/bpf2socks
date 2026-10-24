// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#include "bpf/runtime.h"
#include "core/log.h"
#include "shared/udp6_recovery_netlink.h"

void bpf2socks_udp6_recovery_cleanup(void) {
    if (asterisk_udp6_recovery_reconcile(true) < 0) {
        bpf2socks_log("failed to detach UDP6 recovery filters: errno=%d", errno);
    }
}
void bpf2socks_udp6_recovery_stop(struct bpf2socks_bpf_runtime *runtime) {
    if (!runtime->udp6_recovery_attached && !runtime->udp6_recovery_qdisc_created) return;
    bpf2socks_udp6_recovery_cleanup();
    if (runtime->udp6_recovery_qdisc_created) {
        unsigned loopback = if_nametoindex("lo"), total = 0U;
        if (loopback != 0U && asterisk_udp6_recovery_inspect(loopback, ASTERISK_UDP6_RECOVERY_INGRESS, "", &total) >= 0 &&
            asterisk_udp6_recovery_inspect(loopback, ASTERISK_UDP6_RECOVERY_EGRESS, "", &total) >= 0 && total == 0U) {
            struct asterisk_udp6_recovery_request request;
            asterisk_udp6_recovery_request_init(&request, RTM_DELQDISC, NLM_F_ACK, loopback, TC_H_CLSACT);
            request.message.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0U);
            (void)asterisk_udp6_recovery_transaction(&request);
        }
    }
    runtime->udp6_recovery_attached = false;
    runtime->udp6_recovery_qdisc_created = false;
}

int bpf2socks_udp6_recovery_start(struct bpf2socks_bpf_runtime *runtime) {
    if (runtime->udp6_recover_prog_fd < 0) return 0;
    unsigned loopback = if_nametoindex("lo"), total = 0U;
    if (loopback == 0U) return -1;
    int ingress = asterisk_udp6_recovery_inspect(loopback, ASTERISK_UDP6_RECOVERY_INGRESS, "b2s_u6_recover", &total);
    int egress = asterisk_udp6_recovery_inspect(loopback, ASTERISK_UDP6_RECOVERY_EGRESS, "b2s_u6_record", &total);
    if (ingress < 0 || egress < 0) return -1;
    if (ingress == 2 || egress == 2) { errno = EEXIST; return -1; }
    bpf2socks_udp6_recovery_cleanup();
    struct asterisk_udp6_recovery_request request;
    asterisk_udp6_recovery_request_init(&request, RTM_NEWQDISC, NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, loopback, TC_H_CLSACT);
    request.message.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0U);
    (void)asterisk_udp6_recovery_attribute(&request, TCA_KIND, "clsact", 7U);
    if (asterisk_udp6_recovery_transaction(&request) == 0) runtime->udp6_recovery_qdisc_created = true;
    else if (errno != EEXIST) return -1;
    runtime->udp6_recovery_attached = true;
    if (asterisk_udp6_recovery_filter_change(loopback, ASTERISK_UDP6_RECOVERY_EGRESS, runtime->udp6_record_prog_fd, false) < 0 ||
        asterisk_udp6_recovery_filter_change(loopback, ASTERISK_UDP6_RECOVERY_INGRESS, runtime->udp6_recover_prog_fd, false) < 0) {
        int saved = errno; bpf2socks_udp6_recovery_stop(runtime); errno = saved; return -1;
    }
    return 0;
}
