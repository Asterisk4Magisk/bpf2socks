// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf/cgroup_prog.h"
#include "bpf/runtime.h"
#include "bpf/syscall.h"
#include "bpf2socks.h"
#include "core/token.h"
#include "core/util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Instruction-level generation of the cgroup connect/sendmsg/recvmsg/getpeername programs. */
#define BPF2SOCKS_MAX_INLINE_BYPASS_UIDS 16U
#define BPF2SOCKS_IKE_PORT 500U
#define BPF2SOCKS_NAT_T_PORT 4500U
#define BPF2SOCKS_DNS_TETHER_UID 1052U
#define BPF2SOCKS_LOOPBACK_IFINDEX 1U

#define BPF_ALU64_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU64_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_ALU32_IMM_OP(OP, DST, IMM) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K, .dst_reg = DST, .imm = (int32_t)(IMM)})
#define BPF_ALU32_REG_OP(OP, DST, SRC) ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC})
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG_OP(BPF_MOV, DST, SRC)
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM_OP(BPF_MOV, DST, IMM)
#define BPF_MOV32_REG(DST, SRC) BPF_ALU32_REG_OP(BPF_MOV, DST, SRC)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_JMP_IMM_OP(OP, DST, IMM, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K, .dst_reg = DST, .off = OFF, .imm = (int32_t)(IMM)})
#define BPF_JMP_REG_OP(OP, DST, SRC, OFF) ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X, .dst_reg = DST, .src_reg = SRC, .off = OFF})
#define BPF_CALL_FUNC(FUNC) ((struct bpf_insn){.code = BPF_JMP | BPF_CALL, .imm = FUNC})
#define BPF_EXIT_INSN() ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT})
#define BPF_ENDIAN_OP(DST, SIZE) ((struct bpf_insn){.code = BPF_ALU | BPF_END | BPF_TO_BE, .dst_reg = DST, .imm = SIZE})

enum {
    STACK_UID_KEY = -4,
    STACK_IFINDEX_KEY = -8,
    STACK_LPM4_KEY = -16,
    STACK_LPM6_KEY = -40,
    STACK_TOKEN_KEY = -96,
    STACK_ORIGINAL_DST = -144,
    STACK_UDP_PEER_KEY = -168,
    STACK_UDP_PEER_VALUE = -192,
    STACK_SAVED_V6_LAST_WORD = -200,
    STACK_SAVED_PORT = -204,
    STACK_SAVED_V6_WORD0 = -208,
    STACK_SAVED_V6_WORD1 = -212,
    STACK_SAVED_V6_WORD2 = -216,
    STACK_SAVED_V4_ADDR = -220,
    STACK_SAVED_V4_PORT = -224,
};

struct bpf_builder {
    /* IPv6 emits both native and v4-mapped paths, including UID policies. */
    struct bpf_insn insns[1024];
    size_t count;
    bool overflow;
};

static void emit(struct bpf_builder *builder, struct bpf_insn insn) {
    if (builder->count < BPF2SOCKS_ARRAY_SIZE(builder->insns)) {
        builder->insns[builder->count++] = insn;
    } else {
        builder->overflow = true;
    }
}

static size_t emit_jump(struct bpf_builder *builder, struct bpf_insn insn) {
    size_t index = builder->count;
    emit(builder, insn);
    return index;
}

static void patch_jump(struct bpf_builder *builder, size_t jump_index, size_t target_index) {
    builder->insns[jump_index].off = (int16_t)(target_index - jump_index - 1U);
}

static void emit_ld_map_fd(struct bpf_builder *builder, int dst_reg, int map_fd) {
    emit(builder, (struct bpf_insn){
        .code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = (uint8_t)dst_reg,
        .src_reg = BPF_PSEUDO_MAP_FD,
        .imm = map_fd,
    });
    emit(builder, (struct bpf_insn){.code = 0, .imm = 0});
}

static void emit_ctx_st32(struct bpf_builder *builder, int offset, uint32_t imm) {
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, imm));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, offset));
}

static size_t emit_exit(struct bpf_builder *builder, int result) {
    size_t label = builder->count;
    emit(builder, BPF_MOV64_IMM(BPF_REG_0, result));
    emit(builder, BPF_EXIT_INSN());
    return label;
}

size_t bpf2socks_cgroup_prog_inline_bypass_uid_count(const struct bpf2socks_policy_config *policy) {
    if (policy == NULL) return 0U;
    return policy->bypass_uid_count < BPF2SOCKS_MAX_INLINE_BYPASS_UIDS
        ? policy->bypass_uid_count
        : BPF2SOCKS_MAX_INLINE_BYPASS_UIDS;
}

static void emit_zero_region(struct bpf_builder *builder, int base_off, size_t size) {
    for (size_t off = 0; off < size; off += sizeof(uint32_t)) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, (int16_t)(base_off + (int)off), 0));
    }
}

static void emit_self_gid_bypass_check_from_current_uid_gid(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (policy == NULL || !policy->self_bypass_gid_enabled) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_0));
    emit(builder, BPF_ALU64_IMM_OP(BPF_RSH, BPF_REG_8, 32));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, policy->self_bypass_gid, 0));
}

static void emit_self_bypass_policy(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (policy == NULL || !policy->self_bypass_gid_enabled) return;

    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_uid_gid));
    emit_self_gid_bypass_check_from_current_uid_gid(builder, policy, bypass_jumps, bypass_jump_count);
}

/*
 * Bypass a socket the app bound explicitly to a network other than a default
 * one (Network.bindSocket, bindProcessToNetwork), so a captive portal login
 * or a cellular-only service uses the network it chose. Sockets bound to a
 * default network, as QUIC connection migration does, stay proxied, and so
 * does everything while userspace has not published the default networks.
 */
static void emit_explicit_network_bypass(
    struct bpf_builder *builder,
    int default_network_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (default_network_map_fd < 0) return;
    size_t skip[4];
    size_t skip_count = 0U;
    emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
    skip[skip_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_2, offsetof(struct bpf_sock, mark)));
    emit(builder, BPF_MOV64_REG(BPF_REG_4, BPF_REG_3));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_4, BPF2SOCKS_FWMARK_EXPLICIT));
    skip[skip_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_4, 0, 0));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_3, 0xffffU));
    skip[skip_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, STACK_IFINDEX_KEY));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_UID_KEY, BPF2SOCKS_DEFAULT_NETWORK_READY_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, default_network_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UID_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    skip[skip_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_ld_map_fd(builder, BPF_REG_1, default_network_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_IFINDEX_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    for (size_t i = 0U; i < skip_count; ++i) patch_jump(builder, skip[i], builder->count);
}

/*
 * Bypass sockets a token rewrite cannot carry: UDP-Lite, which the UDP
 * sendmsg hooks also see but the bridge cannot receive, and a socket bound
 * to a device other than loopback, whose datagrams cannot reach a loopback
 * token and whose replies arriving on loopback would not match it.
 */
static void emit_socket_shape_bypass(
    struct bpf_builder *builder,
    enum bpf_attach_type attach_type,
    int default_network_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG || attach_type == BPF_CGROUP_UDP6_SENDMSG) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
    }
    emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
    size_t no_sock = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_2, offsetof(struct bpf_sock, bound_dev_if)));
    size_t unbound = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_3, BPF2SOCKS_LOOPBACK_IFINDEX, 0));
    patch_jump(builder, no_sock, builder->count);
    patch_jump(builder, unbound, builder->count);
    emit_explicit_network_bypass(builder, default_network_map_fd, bypass_jumps, bypass_jump_count);
}

static void emit_uid_policy(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    int uid_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (policy == NULL) return;
    size_t inline_count = bpf2socks_cgroup_prog_inline_bypass_uid_count(policy);
    bool needs_map = uid_map_fd >= 0;
    if (inline_count == 0U && !needs_map && policy->mode == BPF2SOCKS_MODE_GLOBAL) return;

    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_uid_gid));
    emit(builder, BPF_MOV32_REG(BPF_REG_7, BPF_REG_0));
    for (size_t i = 0; i < inline_count; ++i) {
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, policy->bypass_uids[i], 0));
    }

    if (!needs_map) {
        if (policy->mode != BPF2SOCKS_MODE_GLOBAL) {
            drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        }
        return;
    }

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UID_KEY));
    emit_ld_map_fd(builder, BPF_REG_1, uid_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UID_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    emit(builder, BPF_MOV64_IMM(BPF_REG_8, 0));
    size_t uid_not_found = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 0));
    patch_jump(builder, uid_not_found, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, BPF2SOCKS_UID_BYPASS));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));

    if (policy->mode == BPF2SOCKS_MODE_GLOBAL) {
        return;
    }

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, BPF2SOCKS_UID_SELECTED));
    if (policy->mode == BPF2SOCKS_MODE_WHITELIST) {
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    } else if (policy->mode == BPF2SOCKS_MODE_BLACKLIST) {
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    } else {
        drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    }
}

/* Explicit UID bypass precedes marked DNS for both protocols. Legacy mode keeps
 * the existing UDP behavior. UID helpers run before loading destinations. */
static void emit_tcp_dns_forced_bypass(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    int uid_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    if (policy == NULL || !policy->enable_dns_hijack) return;
    size_t skip = (size_t)-1;
    if (!policy->enable_dns_enhancement && protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        skip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_STREAM, 0));
    } else if (!policy->enable_dns_enhancement && protocol != BPF2SOCKS_PROTO_TCP) {
        return;
    }
    struct bpf2socks_policy_config bypass_only = *policy;
    bypass_only.mode = BPF2SOCKS_MODE_GLOBAL;
    emit_uid_policy(builder, &bypass_only, uid_map_fd, bypass_jumps,
        bypass_jump_count, drop_jumps, drop_jump_count);
    if (skip != (size_t)-1) patch_jump(builder, skip, builder->count);
}

static void emit_dns_enhancement_policy(
    struct bpf_builder *builder,
    uint8_t port_reg,
    size_t *force_proxy_jumps,
    size_t *force_proxy_jump_count,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    size_t not_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, port_reg, htons(53), 0));
    emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
    size_t no_sock = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_2, offsetof(struct bpf_sock, mark)));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_3, BPF2SOCKS_DNS_MARK_MASK));
    bypass_jumps[(*bypass_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, BPF2SOCKS_DNS_DIRECT_MARK, 0));
    force_proxy_jumps[(*force_proxy_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, BPF2SOCKS_DNS_PROXY_DECISION, 0));
    patch_jump(builder, no_sock, builder->count);
    /* Match the iptables DNS exception after explicit marks and forced bypasses.
     * UDP sendmsg hooks also see UDP-Lite, which is not DNS over UDP. */
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
    size_t tcp_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, BPF2SOCKS_PROTO_TCP, 0));
    size_t not_dns_protocol = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
    patch_jump(builder, tcp_dns, builder->count);
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_current_uid_gid));
    emit(builder, BPF_MOV32_REG(BPF_REG_0, BPF_REG_0));
    force_proxy_jumps[(*force_proxy_jump_count)++] =
        emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, BPF2SOCKS_DNS_TETHER_UID, 0));
    patch_jump(builder, not_dns_protocol, builder->count);
    /* Other unmarked DNS reaches UID selection and then skips CIDR policy. */
    patch_jump(builder, not_dns, builder->count);
}

static void emit_ipv4_dns_force_proxy_policy_from_regs(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    uint8_t protocol,
    bool protocol_from_context,
    size_t *force_proxy_jumps,
    size_t *force_proxy_jump_count,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (policy == NULL || !policy->enable_dns_hijack) return;
    if (policy->enable_dns_enhancement) {
        emit_dns_enhancement_policy(builder, BPF_REG_8, force_proxy_jumps,
            force_proxy_jump_count, bypass_jumps, bypass_jump_count);
        return;
    }

    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        size_t tcp_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_STREAM, 0));
        size_t not_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_DGRAM, 0));
        patch_jump(builder, tcp_dns, builder->count);
        force_proxy_jumps[(*force_proxy_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, htons(53), 0));
        patch_jump(builder, not_dns, builder->count);
    } else if (protocol == BPF2SOCKS_PROTO_UDP || protocol == BPF2SOCKS_PROTO_TCP) {
        force_proxy_jumps[(*force_proxy_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, htons(53), 0));
    }
}

static void emit_ipv6_dns_force_proxy_policy_from_regs(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    uint8_t protocol,
    bool protocol_from_context,
    size_t *force_proxy_jumps,
    size_t *force_proxy_jump_count,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (policy == NULL || !policy->enable_dns_hijack) return;
    if (policy->enable_dns_enhancement) {
        emit_dns_enhancement_policy(builder, BPF_REG_5, force_proxy_jumps,
            force_proxy_jump_count, bypass_jumps, bypass_jump_count);
        /* The UID helper clobbers R1-R5; the caller saved the IPv6 destination. */
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_10, STACK_SAVED_PORT));
        return;
    }

    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        size_t tcp_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, SOCK_STREAM, 0));
        size_t not_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_DGRAM, 0));
        patch_jump(builder, tcp_dns, builder->count);
        force_proxy_jumps[(*force_proxy_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, htons(53), 0));
        patch_jump(builder, not_dns, builder->count);
    } else if (protocol == BPF2SOCKS_PROTO_UDP || protocol == BPF2SOCKS_PROTO_TCP) {
        force_proxy_jumps[(*force_proxy_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, htons(53), 0));
    }
}

static size_t emit_connected_udp_dns_continue(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    uint8_t port_reg) {
    if (policy == NULL || !policy->enable_dns_hijack) return (size_t)-1;

    size_t not_dns = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, port_reg, htons(53), 0));
    size_t dns_continue = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    patch_jump(builder, not_dns, builder->count);
    return dns_continue;
}

static void patch_connected_udp_dns_continue(struct bpf_builder *builder, size_t jump) {
    if (jump != (size_t)-1) {
        patch_jump(builder, jump, builder->count);
    }
}

static void emit_ipsec_udp_bypass_from_port(
    struct bpf_builder *builder,
    uint8_t protocol,
    bool protocol_from_context,
    uint8_t port_reg,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_DGRAM, 0));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(BPF2SOCKS_IKE_PORT), 0));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(BPF2SOCKS_NAT_T_PORT), 0));
        patch_jump(builder, not_udp, builder->count);
    } else if (protocol == BPF2SOCKS_PROTO_UDP) {
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(BPF2SOCKS_IKE_PORT), 0));
        bypass_jumps[(*bypass_jump_count)++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, port_reg, htons(BPF2SOCKS_NAT_T_PORT), 0));
    }
}

static void emit_connected_udp_original_flag(
    struct bpf_builder *builder,
    bool protocol_from_context) {
    if (!protocol_from_context) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
    emit(builder, BPF_ST_MEM(
        BPF_B,
        BPF_REG_10,
        STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, flags),
        BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP));
    patch_jump(builder, not_udp, builder->count);
}

static void emit_udp_peer_cache_update_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct bpf2socks_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, protocol), BPF2SOCKS_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v4mapped(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct bpf2socks_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, family), AF_INET));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, protocol), BPF2SOCKS_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr)));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct bpf2socks_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, family), AF_INET6));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, protocol), BPF2SOCKS_PROTO_UDP));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr) + 12));

    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
}

static void emit_udp_peer_cache_update(
    struct bpf_builder *builder,
    int udp_peer_map_fd,
    bool ipv6,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    if (ipv6) {
        emit_udp_peer_cache_update_v6(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    } else {
        emit_udp_peer_cache_update_v4(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
    }
}

static void emit_udp_peer_cache_restore_v4(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    size_t missing_ip = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_8, 0, 0));
    patch_jump(builder, missing_ip, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, family), AF_INET));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, port)));

    size_t done = builder->count;
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, done);
    patch_jump(builder, no_peer, done);
    patch_jump(builder, wrong_family, done);
    patch_jump(builder, wrong_proto, done);
}

static void emit_udp_peer_cache_restore_v6(
    struct bpf_builder *builder,
    int udp_peer_map_fd) {
    if (udp_peer_map_fd < 0) return;

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
    size_t missing_addr = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    size_t has_complete_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, 0, 0));
    patch_jump(builder, missing_addr, builder->count);

    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, family), AF_INET6));
    emit_ld_map_fd(builder, BPF_REG_1, udp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    size_t no_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, family)));
    size_t wrong_family = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, protocol)));
    size_t wrong_proto = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, addr)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, addr) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, addr) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, addr) + 12));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_5, BPF_REG_0, offsetof(struct bpf2socks_udp_peer_value, port)));
    size_t restored_peer = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t fallback = builder->count;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    size_t done = builder->count;
    patch_jump(builder, restored_peer, done);
    patch_jump(builder, has_complete_peer, done);
    patch_jump(builder, no_cookie, fallback);
    patch_jump(builder, no_peer, fallback);
    patch_jump(builder, wrong_family, fallback);
    patch_jump(builder, wrong_proto, fallback);
}

/*
 * Remembers a proxied TCP connection's original peer by socket cookie. The
 * bridge consumes the TCP token on accept, so getpeername() could not map the
 * token back otherwise. Emitted only on a CONNECT rewrite path, where the
 * original destination is on the stack; UDP keeps its own peer cache.
 */
static void emit_tcp_peer_record(struct bpf_builder *builder, int tcp_peer_map_fd) {
    if (tcp_peer_map_fd < 0) return;
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
    size_t not_tcp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_TCP, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    size_t no_cookie = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    /* The key family stays zero: a cookie already names one socket. */
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit_zero_region(builder, STACK_UDP_PEER_VALUE, sizeof(struct bpf2socks_udp_peer_value));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, family)));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_2, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, family)));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, protocol), BPF2SOCKS_PROTO_TCP));
    /* The stack holds the port in host order; keep it in network order for the context. */
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, port)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_2, STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, port)));
    for (int word = 0; word < 4; ++word) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10,
            STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr) + word * 4));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2,
            STACK_UDP_PEER_VALUE + (int)offsetof(struct bpf2socks_udp_peer_value, addr) + word * 4));
    }
    emit_ld_map_fd(builder, BPF_REG_1, tcp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_UDP_PEER_VALUE));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    patch_jump(builder, not_tcp, builder->count);
    patch_jump(builder, no_cookie, builder->count);
}

/*
 * GETPEERNAME for a stream socket: restore the peer recorded at CONNECT. Jumps
 * to done when nothing is recorded or after writing the original peer; an
 * IPv6 socket gets an IPv4 peer back as a v4-mapped address.
 */
static void emit_tcp_peer_restore(
    struct bpf_builder *builder,
    int tcp_peer_map_fd,
    bool ipv6,
    size_t *done_jumps,
    size_t *done_jump_count) {
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    done_jumps[(*done_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit_zero_region(builder, STACK_UDP_PEER_KEY, sizeof(struct bpf2socks_udp_peer_key));
    emit(builder, BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, STACK_UDP_PEER_KEY + (int)offsetof(struct bpf2socks_udp_peer_key, cookie)));
    emit_ld_map_fd(builder, BPF_REG_1, tcp_peer_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_UDP_PEER_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    done_jumps[(*done_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    /* emit_ctx_st32() uses R0 as scratch: keep the map value in R7. */
    emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_7, offsetof(struct bpf2socks_udp_peer_value, family)));
    if (!ipv6) {
        done_jumps[(*done_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET, 0));
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_7, offsetof(struct bpf2socks_udp_peer_value, addr)));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_3, offsetof(struct bpf_sock_addr, user_ip4)));
    } else {
        size_t mapped = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, AF_INET, 0));
        done_jumps[(*done_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, AF_INET6, 0));
        for (int word = 0; word < 4; ++word) {
            emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_7, offsetof(struct bpf2socks_udp_peer_value, addr) + word * 4));
            emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_3, offsetof(struct bpf_sock_addr, user_ip6) + word * 4));
        }
        size_t port = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        patch_jump(builder, mapped, builder->count);
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
        emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_7, offsetof(struct bpf2socks_udp_peer_value, addr)));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_3, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        patch_jump(builder, port, builder->count);
    }
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_7, offsetof(struct bpf2socks_udp_peer_value, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_3, offsetof(struct bpf_sock_addr, user_port)));
    done_jumps[(*done_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static void emit_ipv4_policy_checks_from_regs(
    struct bpf_builder *builder,
    int proxy_cidr4_map_fd,
    int bypass_private_cidr4_map_fd,
    int local_interface_cidr4_map_fd,
    int direct_cidr4_map_fd,
    int ignored_ifindex_map_fd,
    int ignored_route_cidr4_map_fd,
    size_t *force_proxy_jumps,
    size_t *force_proxy_jump_count,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));

    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    emit(builder, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, 0xff000000U));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0x7f000000U, 0));

    if (local_interface_cidr4_map_fd >= 0) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM4_KEY, 32));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM4_KEY + (int)offsetof(struct bpf2socks_lpm4_key, addr)));
        emit_ld_map_fd(builder, BPF_REG_1, local_interface_cidr4_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM4_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (proxy_cidr4_map_fd >= 0) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM4_KEY, 32));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM4_KEY + (int)offsetof(struct bpf2socks_lpm4_key, addr)));
        emit_ld_map_fd(builder, BPF_REG_1, proxy_cidr4_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM4_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        force_proxy_jumps[(*force_proxy_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (bypass_private_cidr4_map_fd >= 0) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM4_KEY, 32));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM4_KEY + (int)offsetof(struct bpf2socks_lpm4_key, addr)));
        emit_ld_map_fd(builder, BPF_REG_1, bypass_private_cidr4_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM4_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (ignored_ifindex_map_fd >= 0) {
        emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
        size_t no_sock = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_2, offsetof(struct bpf_sock, bound_dev_if)));
        size_t no_bound_if = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, STACK_IFINDEX_KEY));
        emit_ld_map_fd(builder, BPF_REG_1, ignored_ifindex_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_IFINDEX_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
        patch_jump(builder, no_sock, builder->count);
        patch_jump(builder, no_bound_if, builder->count);
    }

    if (ignored_route_cidr4_map_fd >= 0) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM4_KEY, 32));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM4_KEY + (int)offsetof(struct bpf2socks_lpm4_key, addr)));
        emit_ld_map_fd(builder, BPF_REG_1, ignored_route_cidr4_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM4_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (direct_cidr4_map_fd >= 0) {
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM4_KEY, 32));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM4_KEY + (int)offsetof(struct bpf2socks_lpm4_key, addr)));
        emit_ld_map_fd(builder, BPF_REG_1, direct_cidr4_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM4_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }
}

static void emit_ipv4_mapped_ipv6_check_jumps(
    struct bpf_builder *builder,
    size_t *not_mapped_jumps,
    size_t *not_mapped_jump_count) {
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 32));
    not_mapped_jumps[(*not_mapped_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0x0000ffffU, 0));
}

static void emit_ipv6_policy_checks(
    struct bpf_builder *builder,
    int proxy_cidr6_map_fd,
    int bypass_private_cidr6_map_fd,
    int local_interface_cidr6_map_fd,
    int direct_cidr6_map_fd,
    int ignored_ifindex_map_fd,
    int ignored_route_cidr6_map_fd,
    size_t *force_proxy_jumps,
    size_t *force_proxy_jump_count,
    size_t *bypass_jumps,
    size_t *bypass_jump_count) {
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
    emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
    size_t not_zero_or_loopback = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_4));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_3, 32));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
    bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 1, 0));
    patch_jump(builder, not_zero_or_loopback, builder->count);

    bool needs_lpm6_key =
        proxy_cidr6_map_fd >= 0 ||
        ignored_route_cidr6_map_fd >= 0 ||
        bypass_private_cidr6_map_fd >= 0 ||
        local_interface_cidr6_map_fd >= 0 ||
        direct_cidr6_map_fd >= 0;
    if (needs_lpm6_key) {
        emit_zero_region(builder, STACK_LPM6_KEY, sizeof(struct bpf2socks_lpm6_key));
        emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_LPM6_KEY, 128));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_LPM6_KEY + (int)offsetof(struct bpf2socks_lpm6_key, addr)));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_LPM6_KEY + (int)offsetof(struct bpf2socks_lpm6_key, addr) + 4));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_LPM6_KEY + (int)offsetof(struct bpf2socks_lpm6_key, addr) + 8));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_LPM6_KEY + (int)offsetof(struct bpf2socks_lpm6_key, addr) + 12));
    }

    if (local_interface_cidr6_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, local_interface_cidr6_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM6_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (proxy_cidr6_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, proxy_cidr6_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM6_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        force_proxy_jumps[(*force_proxy_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (bypass_private_cidr6_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, bypass_private_cidr6_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM6_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (ignored_ifindex_map_fd >= 0) {
        emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
        size_t no_sock = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_2, offsetof(struct bpf_sock, bound_dev_if)));
        size_t no_bound_if = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, 0, 0));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_3, STACK_IFINDEX_KEY));
        emit_ld_map_fd(builder, BPF_REG_1, ignored_ifindex_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_IFINDEX_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
        patch_jump(builder, no_sock, builder->count);
        patch_jump(builder, no_bound_if, builder->count);
    }

    if (ignored_route_cidr6_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, ignored_route_cidr6_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM6_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }

    if (direct_cidr6_map_fd >= 0) {
        emit_ld_map_fd(builder, BPF_REG_1, direct_cidr6_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_LPM6_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        bypass_jumps[(*bypass_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    }
}

/* r9 = random IPv4 token in network order. */
static void emit_random_token_v4(struct bpf_builder *builder, uint32_t token_prefix, uint32_t token_host_mask) {
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
    emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_9, token_host_mask));
    emit(builder, BPF_ALU32_IMM_OP(BPF_OR, BPF_REG_9, token_prefix));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_9, 32));
}

/* dst = cookie ^ (cookie >> 32); clobbers r0-r5. */
static void emit_socket_cookie_fold(struct bpf_builder *builder, int dst_reg) {
    emit(builder, BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_socket_cookie));
    emit(builder, BPF_MOV64_REG(dst_reg, BPF_REG_0));
    emit(builder, BPF_ALU64_IMM_OP(BPF_RSH, dst_reg, 32));
    emit(builder, BPF_ALU64_REG_OP(BPF_XOR, dst_reg, BPF_REG_0));
}

/* dst = (dst ^ src) * multiplier, 32-bit. */
static void emit_hash_mix(struct bpf_builder *builder, int dst_reg, int src_reg, uint32_t multiplier) {
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, dst_reg, src_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_MUL, dst_reg, multiplier));
}

/* dst ^= dst >> shift; clobbers r2. */
static void emit_hash_finish(struct bpf_builder *builder, int dst_reg, uint32_t shift) {
    emit(builder, BPF_MOV32_REG(BPF_REG_2, dst_reg));
    emit(builder, BPF_ALU32_IMM_OP(BPF_RSH, BPF_REG_2, shift));
    emit(builder, BPF_ALU32_REG_OP(BPF_XOR, dst_reg, BPF_REG_2));
}

/*
 * r9 = flow token for an unconnected sendmsg(): a hash of the socket cookie
 * and the raw destination (r7 address, r8 port), so every datagram of a flow
 * maps to the same token instead of a fresh random one.
 */
static void emit_flow_token_v4(struct bpf_builder *builder, uint32_t token_prefix, uint32_t token_host_mask) {
    emit_socket_cookie_fold(builder, BPF_REG_9);
    emit_hash_mix(builder, BPF_REG_9, BPF_REG_7, 0x9e3779b1U);
    emit_hash_mix(builder, BPF_REG_9, BPF_REG_8, 0x85ebca6bU);
    emit_hash_finish(builder, BPF_REG_9, 15U);
    emit(builder, BPF_ALU32_IMM_OP(BPF_AND, BPF_REG_9, token_host_mask));
    emit(builder, BPF_ALU32_IMM_OP(BPF_OR, BPF_REG_9, token_prefix));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_9, 32));
}

/*
 * Publishes the token key and value already on the stack. A flow token is
 * reused when the map still holds the same original destination, and is
 * inserted with BPF_NOEXIST otherwise. A hash collision or an insert race
 * falls back to a random token, published like the non-flow path.
 */
static void emit_publish_token(
    struct bpf_builder *builder,
    int token_map_fd,
    bool flow_token,
    bool ipv6,
    uint32_t token_prefix,
    uint32_t token_host_mask,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    size_t done_jumps[2];
    size_t done_jump_count = 0U;
    size_t collision_jumps[8];
    size_t collision_jump_count = 0U;
    if (flow_token) {
        emit_ld_map_fd(builder, BPF_REG_1, token_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
        size_t missing = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
        for (int off = 0; off < (int)sizeof(struct bpf2socks_original_dst); off += 4) {
            emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_0, off));
            emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, STACK_ORIGINAL_DST + off));
            collision_jumps[collision_jump_count++] =
                emit_jump(builder, BPF_JMP_REG_OP(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
        }
        done_jumps[done_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        patch_jump(builder, missing, builder->count);
        emit_ld_map_fd(builder, BPF_REG_1, token_map_fd);
        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
        emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
        emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
        emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_NOEXIST));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
        done_jumps[done_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
        for (size_t i = 0U; i < collision_jump_count; ++i) patch_jump(builder, collision_jumps[i], builder->count);
        if (ipv6) {
            emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
            emit(builder, BPF_MOV32_REG(BPF_REG_8, BPF_REG_0));
            emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
            emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));
            emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8,
                STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 8));
            emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9,
                STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 12));
        } else {
            emit_random_token_v4(builder, token_prefix, token_host_mask);
            emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9,
                STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));
        }
    }
    emit_ld_map_fd(builder, BPF_REG_1, token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
    emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_3, STACK_ORIGINAL_DST));
    emit(builder, BPF_MOV64_IMM(BPF_REG_4, BPF_ANY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_update_elem));
    drop_jumps[(*drop_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_0, 0, 0));
    for (size_t i = 0U; i < done_jump_count; ++i) patch_jump(builder, done_jumps[i], builder->count);
}

static void emit_token_update_and_rewrite(
    struct bpf_builder *builder,
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    bool flow_token,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t token_prefix = bpf2socks_token_prefix_imm4(
        config->token_ipv4_prefix,
        config->token_ipv4_prefix_bits);
    uint32_t token_host_mask = bpf2socks_token_prefix_host_mask4(config->token_ipv4_prefix_bits);
    if (flow_token) {
        emit_flow_token_v4(builder, token_prefix, token_host_mask);
    } else {
        emit_random_token_v4(builder, token_prefix, token_host_mask);
    }
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct bpf2socks_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port), bridge_port));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr)));
    emit_connected_udp_original_flag(builder, protocol_from_context);
    emit_publish_token(
        builder,
        token_map_fd,
        flow_token,
        false,
        token_prefix,
        token_host_mask,
        drop_jumps,
        drop_jump_count);

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip4)));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(bridge_port));
}

static void emit_token_update_and_rewrite_v6(
    struct bpf_builder *builder,
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    bool flow_token,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t prefix0 = bpf2socks_token_prefix_word6(config->token_ipv6_prefix, 0U);
    uint32_t prefix1 = bpf2socks_token_prefix_word6(config->token_ipv6_prefix, 4U);

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_5, STACK_SAVED_PORT));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_SAVED_V6_WORD2));

    if (flow_token) {
        /* r8/r9 = flow token words from the cookie and the saved destination. */
        emit_socket_cookie_fold(builder, BPF_REG_8);
        emit_hash_mix(builder, BPF_REG_8, BPF_REG_7, 0x9e3779b1U);
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, STACK_SAVED_V6_WORD1));
        emit_hash_mix(builder, BPF_REG_8, BPF_REG_3, 0x85ebca6bU);
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, STACK_SAVED_V6_WORD2));
        emit_hash_mix(builder, BPF_REG_8, BPF_REG_3, 0x9e3779b1U);
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
        emit_hash_mix(builder, BPF_REG_8, BPF_REG_3, 0x85ebca6bU);
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_10, STACK_SAVED_PORT));
        emit_hash_mix(builder, BPF_REG_8, BPF_REG_3, 0x9e3779b1U);
        emit_hash_finish(builder, BPF_REG_8, 15U);
        emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_8));
        emit(builder, BPF_ALU32_IMM_OP(BPF_MUL, BPF_REG_9, 0xc2b2ae35U));
        emit_hash_finish(builder, BPF_REG_9, 13U);
    } else {
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
        emit(builder, BPF_MOV32_REG(BPF_REG_8, BPF_REG_0));
        emit(builder, BPF_CALL_FUNC(BPF_FUNC_get_prandom_u32));
        emit(builder, BPF_MOV32_REG(BPF_REG_9, BPF_REG_0));
    }

    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct bpf2socks_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port), bridge_port));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr), prefix0));
    emit(builder, BPF_ST_MEM(BPF_W, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 4, prefix1));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 12));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, family), AF_INET6));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, protocol)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_PORT));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_4, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, port)));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_10, STACK_SAVED_V6_WORD1));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_SAVED_V6_WORD2));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr) + 4));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr) + 12));
    emit_connected_udp_original_flag(builder, protocol_from_context);
    emit_publish_token(
        builder,
        token_map_fd,
        flow_token,
        true,
        0U,
        0U,
        drop_jumps,
        drop_jump_count);

    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), prefix0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, prefix1);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(bridge_port));
}

static void emit_ipv4_mapped_token_update_and_rewrite(
    struct bpf_builder *builder,
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    bool flow_token,
    size_t *drop_jumps,
    size_t *drop_jump_count) {
    uint32_t token_prefix = bpf2socks_token_prefix_imm4(
        config->token_ipv4_prefix,
        config->token_ipv4_prefix_bits);
    uint32_t token_host_mask = bpf2socks_token_prefix_host_mask4(config->token_ipv4_prefix_bits);
    if (flow_token) {
        emit_flow_token_v4(builder, token_prefix, token_host_mask);
    } else {
        emit_random_token_v4(builder, token_prefix, token_host_mask);
    }
    if (protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_TCP));
        size_t not_udp = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_4, SOCK_DGRAM, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, BPF2SOCKS_PROTO_UDP));
        patch_jump(builder, not_udp, builder->count);
    } else {
        emit(builder, BPF_MOV64_IMM(BPF_REG_5, protocol));
    }

    emit_zero_region(builder, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit_zero_region(builder, STACK_ORIGINAL_DST, sizeof(struct bpf2socks_original_dst));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol)));
    emit(builder, BPF_ST_MEM(BPF_H, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port), bridge_port));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));

    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, family), AF_INET));
    emit(builder, BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_5, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, protocol)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, port)));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_ORIGINAL_DST + (int)offsetof(struct bpf2socks_original_dst, addr)));
    emit_connected_udp_original_flag(builder, protocol_from_context);
    emit_publish_token(
        builder,
        token_map_fd,
        flow_token,
        false,
        token_prefix,
        token_host_mask,
        drop_jumps,
        drop_jump_count);

    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit_ctx_st32(builder, offsetof(struct bpf_sock_addr, user_port), htons(bridge_port));
}

static void emit_ipv4_mapped_ipv4_policy_and_token_from_regs(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    int uid_map_fd,
    int proxy_cidr4_map_fd,
    int bypass_private_cidr4_map_fd,
    int local_interface_cidr4_map_fd,
    int direct_cidr4_map_fd,
    int ignored_ifindex_map_fd,
    int ignored_route_cidr4_map_fd,
    int token_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    bool flow_token,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    size_t force_proxy_jumps[16];
    size_t force_proxy_jump_count = 0;

    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_SAVED_V4_ADDR));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V4_PORT));
    emit_ipv4_dns_force_proxy_policy_from_regs(
        builder,
        policy,
        protocol,
        protocol_from_context,
        force_proxy_jumps,
        &force_proxy_jump_count, bypass_jumps, bypass_jump_count);
    emit_uid_policy(builder, policy, uid_map_fd, bypass_jumps, bypass_jump_count, drop_jumps, drop_jump_count);
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V4_ADDR));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V4_PORT));
    if (policy->enable_dns_hijack && policy->enable_dns_enhancement) {
        force_proxy_jumps[force_proxy_jump_count++] =
            emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, htons(53), 0));
    }
    emit_ipv4_policy_checks_from_regs(
        builder,
        proxy_cidr4_map_fd,
        bypass_private_cidr4_map_fd,
        local_interface_cidr4_map_fd,
        direct_cidr4_map_fd,
        ignored_ifindex_map_fd,
        ignored_route_cidr4_map_fd,
        force_proxy_jumps,
        &force_proxy_jump_count,
        bypass_jumps,
        bypass_jump_count);
    size_t token_input_label = builder->count;
    for (size_t i = 0; i < force_proxy_jump_count; ++i) {
        patch_jump(builder, force_proxy_jumps[i], token_input_label);
    }
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V4_ADDR));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V4_PORT));
    emit_ipv4_mapped_token_update_and_rewrite(
        builder,
        config,
        token_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        flow_token,
        drop_jumps,
        drop_jump_count);
    allow_jumps[(*allow_jump_count)++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
}

static bool emit_ipv4_mapped_ipv6_branch(
    struct bpf_builder *builder,
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    int uid_map_fd,
    int proxy_cidr4_map_fd,
    int bypass_private_cidr4_map_fd,
    int local_interface_cidr4_map_fd,
    int direct_cidr4_map_fd,
    int ignored_ifindex_map_fd,
    int ignored_route_cidr4_map_fd,
    int token_map_fd,
    int udp_peer_map_fd,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    size_t *bypass_jumps,
    size_t *bypass_jump_count,
    size_t *drop_jumps,
    size_t *drop_jump_count,
    size_t *allow_jumps,
    size_t *allow_jump_count) {
    size_t continue_jumps[8];
    size_t continue_jump_count = 0;
    size_t mapped_jumps[2];
    size_t mapped_jump_count = 0;

    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == BPF2SOCKS_PROTO_UDP && !protocol_from_context) {
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        for (size_t i = 0; i < continue_jump_count; ++i) {
            patch_jump(builder, continue_jumps[i], builder->count);
        }
        continue_jump_count = 0;

        emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_8));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_9));
        emit(builder, BPF_ALU64_REG_OP(BPF_OR, BPF_REG_2, BPF_REG_4));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, 0, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_7, 0));
        emit(builder, BPF_MOV64_IMM(BPF_REG_8, 0));
        emit_udp_peer_cache_restore_v4(builder, udp_peer_map_fd);
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, 0, 0));
        mapped_jumps[mapped_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
    } else if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        emit(builder, BPF_MOV64_REG(BPF_REG_3, BPF_REG_2));
        size_t tcp_connect = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, BPF2SOCKS_PROTO_TCP, 0));
        continue_jumps[continue_jump_count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
        patch_jump(builder, tcp_connect, builder->count);
        emit_ipv4_mapped_ipv6_check_jumps(builder, continue_jumps, &continue_jump_count);
        emit(builder, BPF_MOV64_REG(BPF_REG_7, BPF_REG_4));
        emit(builder, BPF_MOV64_REG(BPF_REG_8, BPF_REG_5));
        size_t tcp_policy = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_3, BPF2SOCKS_PROTO_TCP, 0));
        emit_udp_peer_cache_update_v4mapped(builder, udp_peer_map_fd, bypass_jumps, bypass_jump_count);
        patch_jump(builder, tcp_policy, builder->count);
    } else {
        return false;
    }

    size_t policy_label = builder->count;
    for (size_t i = 0; i < mapped_jump_count; ++i) {
        patch_jump(builder, mapped_jumps[i], policy_label);
    }
    emit_ipv4_mapped_ipv4_policy_and_token_from_regs(
        builder,
        policy,
        config,
        uid_map_fd,
        proxy_cidr4_map_fd,
        bypass_private_cidr4_map_fd,
        local_interface_cidr4_map_fd,
        direct_cidr4_map_fd,
        ignored_ifindex_map_fd,
        ignored_route_cidr4_map_fd,
        token_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        attach_type == BPF_CGROUP_UDP6_SENDMSG && !protocol_from_context,
        bypass_jumps,
        bypass_jump_count,
        drop_jumps,
        drop_jump_count,
        allow_jumps,
        allow_jump_count);
    size_t continue_label = builder->count;
    for (size_t i = 0; i < continue_jump_count; ++i) {
        patch_jump(builder, continue_jumps[i], continue_label);
    }
    return true;
}

/* Reuse the CONNECT token only for an explicit send to that socket's original
 * peer. A new SENDMSG token would not match the connected socket's receive
 * filter. Read the live peer rather than the cookie cache, which can outlive
 * disconnect/reconnect. Called before destination registers are initialized. */
static void emit_connected_udp_send_reuse(
    struct bpf_builder *builder,
    int token_map_fd,
    bool ipv6,
    bool mapped) {
    size_t fallback[16];
    size_t count = 0U;
    int family = ipv6 && !mapped ? AF_INET6 : AF_INET;
    int words = family == AF_INET6 ? 4 : 1;
    int context_addr = ipv6 ? offsetof(struct bpf_sock_addr, user_ip6) :
        offsetof(struct bpf_sock_addr, user_ip4);
    int socket_addr = ipv6 ? offsetof(struct bpf_sock, dst_ip6) :
        offsetof(struct bpf_sock, dst_ip4);

    emit(builder, BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, sk)));
    fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_7, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_7, offsetof(struct bpf_sock, state)));
    fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF_TCP_ESTABLISHED, 0));
    if (mapped) {
        for (int i = 0; i < 3; ++i) {
            uint32_t expected = i == 2 ? htonl(0xffffU) : 0U;
            emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, context_addr + i * 4));
            fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, expected, 0));
            emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_7, socket_addr + i * 4));
            fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, expected, 0));
        }
        context_addr += 12;
        socket_addr += 12;
    }
    emit_zero_region(builder, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), family));
    emit(builder, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol), BPF2SOCKS_PROTO_UDP));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_7, offsetof(struct bpf_sock, dst_port)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_2, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port)));
    for (int i = 0; i < words; ++i) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_7, socket_addr + i * 4));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + i * 4));
    }
    emit_ld_map_fd(builder, BPF_REG_1, token_map_fd);
    emit(builder, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(builder, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
    emit(builder, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_B, BPF_REG_2, BPF_REG_0, offsetof(struct bpf2socks_original_dst, flags)));
    emit(builder, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, BPF2SOCKS_ORIGINAL_DST_FLAG_CONNECTED_UDP));
    fallback[count++] = emit_jump(builder, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, 0, 0));
    emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_3, BPF_REG_0, offsetof(struct bpf2socks_original_dst, port)));
    fallback[count++] = emit_jump(builder, BPF_JMP_REG_OP(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    for (int i = 0; i < words; ++i) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, context_addr + i * 4));
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr) + i * 4));
        fallback[count++] = emit_jump(builder, BPF_JMP_REG_OP(BPF_JNE, BPF_REG_2, BPF_REG_3, 0));
    }
    for (int i = 0; i < words; ++i) {
        emit(builder, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + i * 4));
        emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_2, context_addr + i * 4));
    }
    emit(builder, BPF_LDX_MEM(BPF_H, BPF_REG_2, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port)));
    emit(builder, BPF_ENDIAN_OP(BPF_REG_2, 16));
    emit(builder, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_2, offsetof(struct bpf_sock_addr, user_port)));
    emit_exit(builder, 1);
    for (size_t i = 0U; i < count; ++i) patch_jump(builder, fallback[i], builder->count);
}

int bpf2socks_cgroup_prog_build4(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    int uid_map_fd = maps->uid_map_fd;
    int proxy_cidr4_map_fd = maps->proxy_cidr4_map_fd;
    int bypass_private_cidr4_map_fd = maps->bypass_private_cidr4_map_fd;
    int local_interface_cidr4_map_fd = maps->local_interface_cidr4_map_fd;
    int direct_cidr4_map_fd = maps->direct_cidr4_map_fd;
    int ignored_ifindex_map_fd = maps->ignored_ifindex_map_fd;
    int ignored_route_cidr4_map_fd = maps->ignored_route_cidr4_map_fd;
    int token_map_fd = maps->token_map_fd;
    int udp_peer_map_fd = maps->udp_peer_map_fd;
    int tcp_peer_map_fd = maps->tcp_peer_map_fd;
    int default_network_map_fd = maps->default_network_map_fd;
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t force_proxy_jumps[16];
    size_t force_proxy_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_bypass_policy(&b, policy, bypass_jumps, &bypass_jump_count);
    emit_socket_shape_bypass(&b, attach_type, default_network_map_fd, bypass_jumps, &bypass_jump_count);
    emit_tcp_dns_forced_bypass(&b, policy, uid_map_fd, protocol, protocol_from_context,
        bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG) {
        emit_connected_udp_send_reuse(&b, token_map_fd, false, false);
    }
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipsec_udp_bypass_from_port(
        &b, protocol, protocol_from_context, BPF_REG_8, bypass_jumps, &bypass_jump_count);
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels, so CONNECT must continue to policy.
    // GETPEERNAME restores the original peer on kernels supporting that hook.
    if (attach_type == BPF_CGROUP_INET4_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, BPF2SOCKS_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
        size_t dns_continue = emit_connected_udp_dns_continue(&b, policy, BPF_REG_8);
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, false, bypass_jumps, &bypass_jump_count);
        patch_connected_udp_dns_continue(&b, dns_continue);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP4_SENDMSG && protocol == BPF2SOCKS_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v4(&b, udp_peer_map_fd);
    }
    emit_ipv4_dns_force_proxy_policy_from_regs(
        &b,
        policy,
        protocol,
        protocol_from_context,
        force_proxy_jumps,
        &force_proxy_jump_count, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_SAVED_V4_ADDR));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V4_PORT));
    emit_uid_policy(&b, policy, uid_map_fd, bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V4_ADDR));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V4_PORT));
    if (policy->enable_dns_hijack && policy->enable_dns_enhancement) {
        force_proxy_jumps[force_proxy_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_8, htons(53), 0));
    }
    emit_ipv4_policy_checks_from_regs(
        &b,
        proxy_cidr4_map_fd,
        bypass_private_cidr4_map_fd,
        local_interface_cidr4_map_fd,
        direct_cidr4_map_fd,
        ignored_ifindex_map_fd,
        ignored_route_cidr4_map_fd,
        force_proxy_jumps,
        &force_proxy_jump_count,
        bypass_jumps,
        &bypass_jump_count);
    for (size_t i = 0; i < force_proxy_jump_count; ++i) {
        patch_jump(&b, force_proxy_jumps[i], b.count);
    }
    emit_token_update_and_rewrite(
        &b,
        config,
        token_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        attach_type == BPF_CGROUP_UDP4_SENDMSG && !protocol_from_context,
        drop_jumps,
        &drop_jump_count);
    if (attach_type == BPF_CGROUP_INET4_CONNECT && protocol_from_context) {
        emit_tcp_peer_record(&b, tcp_peer_map_fd);
    }
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return bpf2socks_bpf_prog_load(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

int bpf2socks_cgroup_prog_build6(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    int uid_map_fd = maps->uid_map_fd;
    int proxy_cidr4_map_fd = maps->proxy_cidr4_map_fd;
    int bypass_private_cidr4_map_fd = maps->bypass_private_cidr4_map_fd;
    int local_interface_cidr4_map_fd = maps->local_interface_cidr4_map_fd;
    int direct_cidr4_map_fd = maps->direct_cidr4_map_fd;
    int proxy_cidr6_map_fd = maps->proxy_cidr6_map_fd;
    int bypass_private_cidr6_map_fd = maps->bypass_private_cidr6_map_fd;
    int local_interface_cidr6_map_fd = maps->local_interface_cidr6_map_fd;
    int direct_cidr6_map_fd = maps->direct_cidr6_map_fd;
    int ignored_ifindex_map_fd = maps->ignored_ifindex_map_fd;
    int ignored_route_cidr4_map_fd = maps->ignored_route_cidr4_map_fd;
    int ignored_route_cidr6_map_fd = maps->ignored_route_cidr6_map_fd;
    int token_map_fd = maps->token_map_fd;
    int udp_peer_map_fd = maps->udp_peer_map_fd;
    int tcp_peer_map_fd = maps->tcp_peer_map_fd;
    int default_network_map_fd = maps->default_network_map_fd;
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t force_proxy_jumps[16];
    size_t force_proxy_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_bypass_policy(&b, policy, bypass_jumps, &bypass_jump_count);
    emit_socket_shape_bypass(&b, attach_type, default_network_map_fd, bypass_jumps, &bypass_jump_count);
    emit_tcp_dns_forced_bypass(&b, policy, uid_map_fd, protocol, protocol_from_context,
        bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG) {
        emit_connected_udp_send_reuse(&b, token_map_fd, true, true);
        emit_connected_udp_send_reuse(&b, token_map_fd, true, false);
    }
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipsec_udp_bypass_from_port(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    bool emitted_v4mapped_branch = emit_ipv4_mapped_ipv6_branch(
        &b,
        policy,
        config,
        uid_map_fd,
        proxy_cidr4_map_fd,
        bypass_private_cidr4_map_fd,
        local_interface_cidr4_map_fd,
        direct_cidr4_map_fd,
        ignored_ifindex_map_fd,
        ignored_route_cidr4_map_fd,
        token_map_fd,
        udp_peer_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        attach_type,
        bypass_jumps,
        &bypass_jump_count,
        drop_jumps,
        &drop_jump_count,
        allow_jumps,
        &allow_jump_count);
    if (emitted_v4mapped_branch) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    }
    // Connected UDP send() may not hit UDP_SENDMSG on Android kernels. Rewrite at CONNECT so all
    // packets reach the bridge; UDP6_SENDMSG remains a fallback for sendmsg() callers.
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, protocol)));
        size_t tcp_connect = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_2, BPF2SOCKS_PROTO_TCP, 0));
        bypass_jumps[bypass_jump_count++] =
            emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, BPF2SOCKS_PROTO_UDP, 0));
        size_t dns_continue = emit_connected_udp_dns_continue(&b, policy, BPF_REG_5);
        emit_udp_peer_cache_update(&b, udp_peer_map_fd, true, bypass_jumps, &bypass_jump_count);
        // map_update_elem() invalidates R1-R5. Reload the destination before either the DNS
        // continuation or the common IPv6 policy path reads the address and port registers.
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
        patch_connected_udp_dns_continue(&b, dns_continue);
        patch_jump(&b, tcp_connect, b.count);
    }
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG && protocol == BPF2SOCKS_PROTO_UDP && !protocol_from_context) {
        emit_udp_peer_cache_restore_v6(&b, udp_peer_map_fd);
    }
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_SAVED_V6_WORD0));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_SAVED_V6_WORD1));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_SAVED_V6_WORD2));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_SAVED_V6_LAST_WORD));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_5, STACK_SAVED_PORT));
    emit_ipv6_dns_force_proxy_policy_from_regs(
        &b,
        policy,
        protocol,
        protocol_from_context,
        force_proxy_jumps,
        &force_proxy_jump_count, bypass_jumps, &bypass_jump_count);
    if (!policy->enable_ipv6) {
        if (policy->enable_dns_hijack && policy->enable_dns_enhancement) {
            // IPv6 off still intercepts selected DNS, matching the legacy DNS scope.
            bypass_jumps[bypass_jump_count++] =
                emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_5, htons(53), 0));
            emit_uid_policy(&b, policy, uid_map_fd, bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
            force_proxy_jumps[force_proxy_jump_count++] =
                emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        } else {
            bypass_jumps[bypass_jump_count++] =
                emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));
        }
    } else {
        emit_uid_policy(&b, policy, uid_map_fd, bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V6_WORD0));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V6_WORD1));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_10, STACK_SAVED_V6_WORD2));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
        emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_10, STACK_SAVED_PORT));
        if (policy->enable_dns_hijack && policy->enable_dns_enhancement) {
            force_proxy_jumps[force_proxy_jump_count++] =
                emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_5, htons(53), 0));
        }
        emit_ipv6_policy_checks(
            &b,
            proxy_cidr6_map_fd,
            bypass_private_cidr6_map_fd,
            local_interface_cidr6_map_fd,
            direct_cidr6_map_fd,
            ignored_ifindex_map_fd,
            ignored_route_cidr6_map_fd,
            force_proxy_jumps,
            &force_proxy_jump_count,
            bypass_jumps,
            &bypass_jump_count);
    }
    size_t token_input_label = b.count;
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_10, STACK_SAVED_V6_WORD0));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, STACK_SAVED_V6_WORD1));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_10, STACK_SAVED_V6_WORD2));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_10, STACK_SAVED_V6_LAST_WORD));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_10, STACK_SAVED_PORT));
    for (size_t i = 0; i < force_proxy_jump_count; ++i) {
        patch_jump(&b, force_proxy_jumps[i], token_input_label);
    }
    emit_token_update_and_rewrite_v6(
        &b,
        config,
        token_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        attach_type == BPF_CGROUP_UDP6_SENDMSG && !protocol_from_context,
        drop_jumps,
        &drop_jump_count);
    /* The v4-mapped branch's rewrite joins here too. */
    size_t rewritten_label = b.count;
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit_tcp_peer_record(&b, tcp_peer_map_fd);
    }
    size_t allow_label = emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], rewritten_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return bpf2socks_bpf_prog_load(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

int bpf2socks_cgroup_prog_build_mapped6(
    const struct bpf2socks_policy_config *policy,
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_bpf_runtime *maps,
    uint8_t protocol,
    bool protocol_from_context,
    uint16_t bridge_port,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    int uid_map_fd = maps->uid_map_fd;
    int proxy_cidr4_map_fd = maps->proxy_cidr4_map_fd;
    int bypass_private_cidr4_map_fd = maps->bypass_private_cidr4_map_fd;
    int local_interface_cidr4_map_fd = maps->local_interface_cidr4_map_fd;
    int direct_cidr4_map_fd = maps->direct_cidr4_map_fd;
    int ignored_ifindex_map_fd = maps->ignored_ifindex_map_fd;
    int ignored_route_cidr4_map_fd = maps->ignored_route_cidr4_map_fd;
    int token_map_fd = maps->token_map_fd;
    int udp_peer_map_fd = maps->udp_peer_map_fd;
    int tcp_peer_map_fd = maps->tcp_peer_map_fd;
    int default_network_map_fd = maps->default_network_map_fd;
    struct bpf_builder b = {0};
    size_t bypass_jumps[96];
    size_t bypass_jump_count = 0;
    size_t drop_jumps[16];
    size_t drop_jump_count = 0;
    size_t allow_jumps[16];
    size_t allow_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit_self_bypass_policy(&b, policy, bypass_jumps, &bypass_jump_count);
    emit_socket_shape_bypass(&b, attach_type, default_network_map_fd, bypass_jumps, &bypass_jump_count);
    emit_tcp_dns_forced_bypass(&b, policy, uid_map_fd, protocol, protocol_from_context,
        bypass_jumps, &bypass_jump_count, drop_jumps, &drop_jump_count);
    if (attach_type == BPF_CGROUP_UDP6_SENDMSG) {
        emit_connected_udp_send_reuse(&b, token_map_fd, true, true);
    }
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipsec_udp_bypass_from_port(
        &b, protocol, protocol_from_context, BPF_REG_5, bypass_jumps, &bypass_jump_count);
    (void)emit_ipv4_mapped_ipv6_branch(
        &b,
        policy,
        config,
        uid_map_fd,
        proxy_cidr4_map_fd,
        bypass_private_cidr4_map_fd,
        local_interface_cidr4_map_fd,
        direct_cidr4_map_fd,
        ignored_ifindex_map_fd,
        ignored_route_cidr4_map_fd,
        token_map_fd,
        udp_peer_map_fd,
        protocol,
        protocol_from_context,
        bridge_port,
        attach_type,
        bypass_jumps,
        &bypass_jump_count,
        drop_jumps,
        &drop_jump_count,
        allow_jumps,
        &allow_jump_count);
    size_t allow_label = emit_exit(&b, 1);
    /* Only the v4-mapped rewrite reaches the peer record. */
    size_t rewritten_label = b.count;
    if (attach_type == BPF_CGROUP_INET6_CONNECT && protocol_from_context) {
        emit_tcp_peer_record(&b, tcp_peer_map_fd);
    }
    (void)emit_exit(&b, 1);
    size_t drop_label = emit_exit(&b, 0);

    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    for (size_t i = 0; i < allow_jump_count; ++i) {
        patch_jump(&b, allow_jumps[i], rewritten_label);
    }
    for (size_t i = 0; i < drop_jump_count; ++i) {
        patch_jump(&b, drop_jumps[i], drop_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return bpf2socks_bpf_prog_load(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

int bpf2socks_cgroup_prog_build_reverse4(
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    int tcp_peer_map_fd,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t tcp_done_jumps[8];
    size_t tcp_done_jump_count = 0;
    if (tcp_peer_map_fd >= 0) {
        size_t not_stream = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_STREAM, 0));
        emit_tcp_peer_restore(&b, tcp_peer_map_fd, false, tcp_done_jumps, &tcp_done_jump_count);
        patch_jump(&b, not_stream, b.count);
    }
    size_t non_udp = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_DGRAM, 0));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));

    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_7));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t token_host_mask = bpf2socks_token_prefix_host_mask4(config->token_ipv4_prefix_bits);
    uint32_t token_network_mask = ~token_host_mask;
    uint32_t token_prefix = bpf2socks_token_prefix_imm4(
        config->token_ipv4_prefix,
        config->token_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, token_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, token_prefix, 0));

    emit_zero_region(&b, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol), BPF2SOCKS_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_8, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, token_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct bpf2socks_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip4)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    patch_jump(&b, non_udp, allow_label);
    for (size_t i = 0; i < tcp_done_jump_count; ++i) {
        patch_jump(&b, tcp_done_jumps[i], allow_label);
    }
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return bpf2socks_bpf_prog_load(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

int bpf2socks_cgroup_prog_build_reverse6(
    const struct bpf2socks_runtime_config *config,
    int token_map_fd,
    int tcp_peer_map_fd,
    enum bpf_attach_type attach_type,
    const char *name,
    bool log_error) {
    struct bpf_builder b = {0};
    size_t bypass_jumps[8];
    size_t bypass_jump_count = 0;

    emit(&b, BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6, offsetof(struct bpf_sock_addr, type)));
    size_t tcp_done_jumps[8];
    size_t tcp_done_jump_count = 0;
    if (tcp_peer_map_fd >= 0) {
        size_t not_stream = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_STREAM, 0));
        emit_tcp_peer_restore(&b, tcp_peer_map_fd, true, tcp_done_jumps, &tcp_done_jump_count);
        patch_jump(&b, not_stream, b.count);
    }
    size_t non_udp = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, SOCK_DGRAM, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit_ipv4_mapped_ipv6_check_jumps(&b, bypass_jumps, &bypass_jump_count);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_4));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_2, 32));
    uint32_t token_host_mask = bpf2socks_token_prefix_host_mask4(config->token_ipv4_prefix_bits);
    uint32_t token_network_mask = ~token_host_mask;
    uint32_t token_prefix = bpf2socks_token_prefix_imm4(
        config->token_ipv4_prefix,
        config->token_ipv4_prefix_bits);
    emit(&b, BPF_ALU64_IMM_OP(BPF_AND, BPF_REG_2, token_network_mask));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JNE, BPF_REG_2, token_prefix, 0));

    emit_zero_region(&b, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol), BPF2SOCKS_PROTO_UDP));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_5, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_5, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));

    emit_ld_map_fd(&b, BPF_REG_1, token_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_8, BPF_REG_0, offsetof(struct bpf2socks_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_8, 16));
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6), 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 4, 0);
    emit_ctx_st32(&b, offsetof(struct bpf_sock_addr, user_ip6) + 8, 0xffff0000U);
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_port)));
    size_t v4mapped_allow = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JA, 0, 0, 0));

    size_t ipv6_lookup_label = b.count;
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], ipv6_lookup_label);
    }
    bypass_jump_count = 0;

    emit_zero_region(&b, STACK_TOKEN_KEY, sizeof(struct bpf2socks_token_key));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, family), AF_INET6));
    emit(&b, BPF_ST_MEM(BPF_B, BPF_REG_10, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, protocol), BPF2SOCKS_PROTO_UDP));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_7, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_port)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_6, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_7, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_8, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_9, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_4, STACK_TOKEN_KEY + (int)offsetof(struct bpf2socks_token_key, token_addr) + 12));

    emit_ld_map_fd(&b, BPF_REG_1, token_map_fd);
    emit(&b, BPF_MOV64_REG(BPF_REG_2, BPF_REG_10));
    emit(&b, BPF_ALU64_IMM_OP(BPF_ADD, BPF_REG_2, STACK_TOKEN_KEY));
    emit(&b, BPF_CALL_FUNC(BPF_FUNC_map_lookup_elem));
    bypass_jumps[bypass_jump_count++] = emit_jump(&b, BPF_JMP_IMM_OP(BPF_JEQ, BPF_REG_0, 0, 0));

    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr)));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr) + 4));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr) + 8));
    emit(&b, BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_0, offsetof(struct bpf2socks_original_dst, addr) + 12));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_ip6)));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_8, offsetof(struct bpf_sock_addr, user_ip6) + 4));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_9, offsetof(struct bpf_sock_addr, user_ip6) + 8));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, offsetof(struct bpf_sock_addr, user_ip6) + 12));
    emit(&b, BPF_LDX_MEM(BPF_H, BPF_REG_7, BPF_REG_0, offsetof(struct bpf2socks_original_dst, port)));
    emit(&b, BPF_ENDIAN_OP(BPF_REG_7, 16));
    emit(&b, BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_7, offsetof(struct bpf_sock_addr, user_port)));

    size_t allow_label = emit_exit(&b, 1);
    patch_jump(&b, non_udp, allow_label);
    for (size_t i = 0; i < tcp_done_jump_count; ++i) {
        patch_jump(&b, tcp_done_jumps[i], allow_label);
    }
    for (size_t i = 0; i < bypass_jump_count; ++i) {
        patch_jump(&b, bypass_jumps[i], allow_label);
    }
    patch_jump(&b, v4mapped_allow, allow_label);

    if (b.overflow) {
        errno = EMSGSIZE;
        return -1;
    }
    return bpf2socks_bpf_prog_load(
        b.insns,
        b.count,
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        log_error);
}

int bpf2socks_cgroup_prog_load_noop(enum bpf_attach_type attach_type, const char *name) {
    struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_EXIT_INSN(),
    };
    return bpf2socks_bpf_prog_load(
        insns,
        BPF2SOCKS_ARRAY_SIZE(insns),
        name,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type,
        false);
}

int bpf2socks_cgroup_prog_load_constant(
    enum bpf_prog_type program_type,
    enum bpf_attach_type attach_type,
    int result,
    const char *name) {
    struct bpf_insn insns[] = {
        BPF_MOV64_IMM(BPF_REG_0, result),
        BPF_EXIT_INSN(),
    };
    return bpf2socks_bpf_prog_load(
        insns,
        BPF2SOCKS_ARRAY_SIZE(insns),
        name,
        program_type,
        attach_type,
        false);
}
