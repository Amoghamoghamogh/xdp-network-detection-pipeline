/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * common.h — shared types, constants, and inline helpers for all kernel-space
 * eBPF/XDP modules. Include this before any module-specific headers.
 */

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* ── Ethernet protocol IDs ─────────────────────────────────────────────── */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

/* ── IP header flags ───────────────────────────────────────────────────── */
#define IP_MF     0x2000  /* More Fragments flag */
#define IP_OFFSET 0x1FFF  /* Fragment offset mask */

/* ── IPv6 extension header types ───────────────────────────────────────── */
#define NEXTHDR_FRAGMENT 44

/* ── BPF map sizing ────────────────────────────────────────────────────── */
#define CITADEL_IP_MAP_MAX 65536

/* ── Type aliases ──────────────────────────────────────────────────────── */
typedef __u8 ip_flag_t;
typedef __u8 ipv6_addr_t[16];

/* ── Packet cursor helper ──────────────────────────────────────────────── */

/**
 * parse_and_advance - bounds-checked pointer advance for packet parsing.
 * @cursor:   pointer to the current parse position (updated on success)
 * @data_end: one-past-end of the packet buffer
 * @size:     number of bytes to consume
 *
 * Returns a pointer to the start of the consumed region, or NULL if the
 * region would exceed the packet boundary.
 */
static __always_inline void *parse_and_advance(void **cursor, void *data_end,
                                               __u32 size) {
  void *start = *cursor;
  if (start + size > data_end)
    return NULL;
  *cursor = start + size;
  return start;
}

/* ── IPv6 address copy helper ──────────────────────────────────────────── */

/**
 * copy_ipv6_addr_as_array - copy a struct in6_addr into a flat __u8[16].
 * Needed because BPF verifier rejects direct struct-to-array casts.
 */
static __always_inline void copy_ipv6_addr_as_array(__u8 dst[16],
                                                    const struct in6_addr *src) {
  const __u8 *s = (const __u8 *)src;
#pragma unroll
  for (int i = 0; i < 16; i++)
    dst[i] = s[i];
}
