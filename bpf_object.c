// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "bpf2socks.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern const unsigned char bpf2socks_embedded_bpf_object[];
extern const size_t bpf2socks_embedded_bpf_object_size;

#ifndef R_BPF_64_64
#define R_BPF_64_64 1U
#endif

static bool range_is_valid(size_t offset, size_t size, size_t total) {
    return offset <= total && size <= total - offset;
}

static const Elf64_Shdr *section_at(
    const Elf64_Ehdr *header,
    size_t object_size,
    size_t index) {
    if (index >= header->e_shnum ||
        header->e_shentsize != sizeof(Elf64_Shdr) ||
        !range_is_valid(header->e_shoff, (size_t)header->e_shnum * sizeof(Elf64_Shdr), object_size)) {
        return NULL;
    }
    return (const Elf64_Shdr *)(
        (const uint8_t *)header + header->e_shoff + index * sizeof(Elf64_Shdr));
}

static const char *section_name(
    const Elf64_Ehdr *header,
    size_t object_size,
    const Elf64_Shdr *section) {
    const Elf64_Shdr *strings = section_at(header, object_size, header->e_shstrndx);
    if (strings == NULL || strings->sh_type != SHT_STRTAB ||
        !range_is_valid(strings->sh_offset, strings->sh_size, object_size) ||
        section->sh_name >= strings->sh_size) {
        return NULL;
    }
    return (const char *)header + strings->sh_offset + section->sh_name;
}

static const Elf64_Shdr *find_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    const char *name,
    size_t *index_out) {
    for (size_t index = 0U; index < header->e_shnum; ++index) {
        const Elf64_Shdr *section = section_at(header, object_size, index);
        const char *current = section == NULL ? NULL : section_name(header, object_size, section);
        if (current != NULL && strcmp(current, name) == 0) {
            if (index_out != NULL) *index_out = index;
            return section;
        }
    }
    errno = ENOENT;
    return NULL;
}

static int resolve_map_fd(
    const struct bpf2socks_bpf_runtime *runtime,
    const char *name) {
    struct map_binding {
        const char *name;
        size_t offset;
    };
#define MAP_BINDING(field, symbol) {symbol, offsetof(struct bpf2socks_bpf_runtime, field)}
    static const struct map_binding bindings[] = {
        MAP_BINDING(tc_runtime_control_map_fd, "tc_runtime_control"),
        MAP_BINDING(tc_original_to_token_map_fd, "tc_original_to_token"),
        MAP_BINDING(tc_token_to_original_map_fd, "tc_token_to_original"),
        MAP_BINDING(token_map_fd, "bridge_token_map"),
        MAP_BINDING(proxy_cidr4_map_fd, "proxy_cidr4_map"),
        MAP_BINDING(bypass_private_cidr4_map_fd, "bypass_private_cidr4_map"),
        MAP_BINDING(local_interface_cidr4_map_fd, "local_interface_cidr4_map"),
        MAP_BINDING(direct_cidr4_map_fd, "direct_cidr4_map"),
        MAP_BINDING(proxy_cidr6_map_fd, "proxy_cidr6_map"),
        MAP_BINDING(bypass_private_cidr6_map_fd, "bypass_private_cidr6_map"),
        MAP_BINDING(local_interface_cidr6_map_fd, "local_interface_cidr6_map"),
        MAP_BINDING(direct_cidr6_map_fd, "direct_cidr6_map"),
        MAP_BINDING(reuseport_tcp4_map_fd, "reuseport_tcp4"),
        MAP_BINDING(reuseport_udp4_map_fd, "reuseport_udp4"),
        MAP_BINDING(reuseport_tcp6_map_fd, "reuseport_tcp6"),
        MAP_BINDING(reuseport_udp6_map_fd, "reuseport_udp6"),
        MAP_BINDING(tc_scratch_map_fd, "tc_scratch"),
    };
#undef MAP_BINDING
    for (size_t index = 0U; index < sizeof(bindings) / sizeof(bindings[0]); ++index) {
        if (strcmp(bindings[index].name, name) != 0) continue;
        const int *fd = (const int *)((const uint8_t *)runtime + bindings[index].offset);
        if (*fd >= 0) return *fd;
        errno = EBADF;
        return -1;
    }
    errno = ENOENT;
    return -1;
}

static int relocate_maps(
    const Elf64_Ehdr *header,
    size_t object_size,
    size_t program_section_index,
    struct bpf_insn *instructions,
    size_t instruction_count,
    const struct bpf2socks_bpf_runtime *runtime) {
    for (size_t index = 0U; index < header->e_shnum; ++index) {
        const Elf64_Shdr *relocations = section_at(header, object_size, index);
        if (relocations == NULL || relocations->sh_type != SHT_REL ||
            relocations->sh_info != program_section_index) {
            continue;
        }
        const Elf64_Shdr *symbols = section_at(header, object_size, relocations->sh_link);
        if (symbols == NULL || symbols->sh_type != SHT_SYMTAB ||
            symbols->sh_entsize != sizeof(Elf64_Sym) ||
            !range_is_valid(symbols->sh_offset, symbols->sh_size, object_size)) {
            errno = ENOEXEC;
            return -1;
        }
        const Elf64_Shdr *strings = section_at(header, object_size, symbols->sh_link);
        if (strings == NULL || strings->sh_type != SHT_STRTAB ||
            !range_is_valid(strings->sh_offset, strings->sh_size, object_size) ||
            relocations->sh_entsize != sizeof(Elf64_Rel) ||
            !range_is_valid(relocations->sh_offset, relocations->sh_size, object_size)) {
            errno = ENOEXEC;
            return -1;
        }
        const Elf64_Rel *entries = (const Elf64_Rel *)(
            (const uint8_t *)header + relocations->sh_offset);
        size_t relocation_count = relocations->sh_size / sizeof(Elf64_Rel);
        const Elf64_Sym *symbol_table = (const Elf64_Sym *)(
            (const uint8_t *)header + symbols->sh_offset);
        size_t symbol_count = symbols->sh_size / sizeof(Elf64_Sym);
        const char *string_table = (const char *)header + strings->sh_offset;
        for (size_t relocation_index = 0U;
             relocation_index < relocation_count;
             ++relocation_index) {
            const Elf64_Rel *relocation = &entries[relocation_index];
            size_t symbol_index = ELF64_R_SYM(relocation->r_info);
            if (ELF64_R_TYPE(relocation->r_info) != R_BPF_64_64 ||
                symbol_index >= symbol_count ||
                relocation->r_offset % sizeof(struct bpf_insn) != 0U) {
                errno = ENOEXEC;
                return -1;
            }
            size_t instruction_index = relocation->r_offset / sizeof(struct bpf_insn);
            const Elf64_Sym *symbol = &symbol_table[symbol_index];
            if (instruction_index + 1U >= instruction_count ||
                symbol->st_name >= strings->sh_size) {
                errno = ENOEXEC;
                return -1;
            }
            int map_fd = resolve_map_fd(runtime, string_table + symbol->st_name);
            if (map_fd < 0) return -1;
            instructions[instruction_index].src_reg = BPF_PSEUDO_MAP_FD;
            instructions[instruction_index].imm = map_fd;
            instructions[instruction_index + 1U].imm = 0;
        }
        return 0;
    }
    errno = ENOEXEC;
    return -1;
}

static int load_program_section(
    const Elf64_Ehdr *header,
    size_t object_size,
    const char *section_name_value,
    const char *program_name,
    enum bpf_prog_type program_type,
    enum bpf_attach_type expected_attach_type,
    const struct bpf2socks_bpf_runtime *runtime,
    bool log_error) {
    size_t section_index = 0U;
    const Elf64_Shdr *section = find_section(
        header,
        object_size,
        section_name_value,
        &section_index);
    if (section == NULL || section->sh_size == 0U ||
        section->sh_size % sizeof(struct bpf_insn) != 0U ||
        !range_is_valid(section->sh_offset, section->sh_size, object_size)) {
        errno = ENOEXEC;
        return -1;
    }
    struct bpf_insn *instructions = malloc(section->sh_size);
    if (instructions == NULL) return -1;
    memcpy(instructions, (const uint8_t *)header + section->sh_offset, section->sh_size);
    size_t instruction_count = section->sh_size / sizeof(struct bpf_insn);
    int result = -1;
    if (relocate_maps(
            header,
            object_size,
            section_index,
            instructions,
            instruction_count,
            runtime) == 0) {
        result = bpf2socks_load_prog(
            instructions,
            instruction_count,
            program_name,
            program_type,
            expected_attach_type,
            log_error);
    }
    int saved = errno;
    free(instructions);
    errno = saved;
    return result;
}

static int pin_program(
    const struct bpf2socks_runtime_config *config,
    int program_fd,
    const char *name) {
    char path[BPF2SOCKS_MAX_PATH_LEN];
    int written = snprintf(
        path,
        sizeof(path),
        "%s/%s",
        config->pinned_object_dir,
        name);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    (void)unlink(path);
    return bpf2socks_pin_fd(program_fd, path);
}

int bpf2socks_load_embedded_tc_programs(
    const struct bpf2socks_runtime_config *config,
    const struct bpf2socks_policy_config *policy,
    struct bpf2socks_bpf_runtime *runtime,
    bool log_error) {
    if (config == NULL || policy == NULL || runtime == NULL ||
        bpf2socks_embedded_bpf_object_size < sizeof(Elf64_Ehdr)) {
        errno = EINVAL;
        return -1;
    }
    const Elf64_Ehdr *header = (const Elf64_Ehdr *)bpf2socks_embedded_bpf_object;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_machine != EM_BPF) {
        errno = ENOEXEC;
        return -1;
    }
    runtime->tc_ingress_prog_fd = load_program_section(
        header,
        bpf2socks_embedded_bpf_object_size,
        "classifier/ingress",
        "b2s_tc_in",
        BPF_PROG_TYPE_SCHED_CLS,
        (enum bpf_attach_type)0,
        runtime,
        log_error);
    if (runtime->tc_ingress_prog_fd < 0) return -1;
    runtime->tc_egress_prog_fd = load_program_section(
        header,
        bpf2socks_embedded_bpf_object_size,
        "classifier/egress",
        "b2s_tc_out",
        BPF_PROG_TYPE_SCHED_CLS,
        (enum bpf_attach_type)0,
        runtime,
        log_error);
    if (runtime->tc_egress_prog_fd < 0) return -1;
    runtime->reuseport_prog_fd = load_program_section(
        header,
        bpf2socks_embedded_bpf_object_size,
        "sk_reuseport",
        "b2s_reuse",
        BPF_PROG_TYPE_SK_REUSEPORT,
        BPF_SK_REUSEPORT_SELECT,
        runtime,
        log_error);
    if (runtime->reuseport_prog_fd < 0 ||
        pin_program(config, runtime->tc_ingress_prog_fd, "tc_ingress") < 0 ||
        pin_program(config, runtime->tc_egress_prog_fd, "tc_egress") < 0) {
        return -1;
    }
    return 0;
}
