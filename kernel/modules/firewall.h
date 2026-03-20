/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * modules/firewall.h — IP-based and port-based packet filtering.
 *
 * Provides:
 *   xdp_ip_filter()   — LPM-trie IP ban check (IPv4 + IPv6)
 *   xdp_port_filter() — (IP, port) ban check for inbound/outbound
 *
 * All stat increments are inlined to avoid function-call overhead in the
 * verifier's instruction budget.
 */

#include "../common.h"
#include "../maps.h"

/* ── Stat helpers ──────────────────────────────────────────────────────── */

static __always_inline void stats_inc_u64(void *map, __u32 key) {
  __u64 *v = bpf_map_lookup_elem(map, &key);
  if (v)
    __sync_fetch_and_add(v, 1);
}

static __always_inline void stats_inc_pkts_dropped(void) {
  stats_inc_u64(&stats_pkts_dropped, 0);
}

static __always_inline void stats_inc_pkts_total(void) {
  stats_inc_u64(&stats_pkts_total, 0);
}

static __always_inline void stats_inc_ipv4_banned(void) {
  stats_inc_u64(&stats_ipv4_banned, 0);
}

static __always_inline void stats_inc_ipv4_recently_banned(void) {
  stats_inc_u64(&stats_ipv4_recently_banned, 0);
}

static __always_inline void stats_inc_ipv6_banned(void) {
  stats_inc_u64(&stats_ipv6_banned, 0);
}

static __always_inline void stats_inc_ipv6_recently_banned(void) {
  stats_inc_u64(&stats_ipv6_recently_banned, 0);
}

static __always_inline void track_dropped_ipv4(__be32 addr) {
  __u64 *v = bpf_map_lookup_elem(&dropped_ipv4_counters, &addr);
  if (v) {
    __sync_fetch_and_add(v, 1);
  } else {
    __u64 one = 1;
    bpf_map_update_elem(&dropped_ipv4_counters, &addr, &one, BPF_ANY);
  }
}

static __always_inline void track_dropped_ipv6(struct in6_addr addr) {
  __u8 *b = (__u8 *)&addr;
  __u64 *v = bpf_map_lookup_elem(&dropped_ipv6_counters, b);
  if (v) {
    __sync_fetch_and_add(v, 1);
  } else {
    __u64 one = 1;
    bpf_map_update_elem(&dropped_ipv6_counters, b, &one, BPF_ANY);
  }
}

/* ── IP filter ─────────────────────────────────────────────────────────── */

/**
 * xdp_ip_filter - check source IP against permanent ban lists.
 *
 * Performs an LPM-trie lookup for the packet's source address.
 * Returns XDP_DROP if the address is banned, XDP_PASS otherwise.
 */
static __noinline int xdp_ip_filter(struct iphdr *iph, struct ipv6hdr *ip6h) {
  if (iph) {
    struct lpm_key_v4 key = { .prefixlen = 32, .addr = iph->saddr };
    if (bpf_map_lookup_elem(&banned_ipv4, &key)) {
      stats_inc_ipv4_banned();
      stats_inc_pkts_dropped();
      track_dropped_ipv4(iph->saddr);
      return XDP_DROP;
    }
  } else if (ip6h) {
    struct lpm_key_v6 key = { .prefixlen = 128 };
    __builtin_memcpy(&key.addr, &ip6h->saddr, sizeof(ip6h->saddr));
    if (bpf_map_lookup_elem(&banned_ipv6, &key)) {
      stats_inc_ipv6_banned();
      stats_inc_pkts_dropped();
      track_dropped_ipv6(ip6h->saddr);
      return XDP_DROP;
    }
  }
  return XDP_PASS;
}

/* ── Port filter ───────────────────────────────────────────────────────── */

/**
 * xdp_port_filter - check (src IP, src port) and (dst IP, dst port) against
 * inbound and outbound port ban maps respectively.
 *
 * Only operates on IPv4 for now; IPv6 port bans can be added analogously.
 * Returns XDP_DROP on a match, XDP_PASS otherwise.
 */
static __noinline int xdp_port_filter(struct iphdr *iph, struct tcphdr *tcph,
                                      struct udphdr *udph) {
  if (!iph)
    return XDP_PASS;

  __be16 src_port = 0, dst_port = 0;
  if (tcph) {
    src_port = tcph->source;
    dst_port = tcph->dest;
  } else if (udph) {
    src_port = udph->source;
    dst_port = udph->dest;
  } else {
    return XDP_PASS;
  }

  struct port_ban_key_v4 inbound = { .addr = iph->saddr, .port = src_port };
  if (bpf_map_lookup_elem(&banned_ports_inbound_v4, &inbound)) {
    stats_inc_pkts_dropped();
    track_dropped_ipv4(iph->saddr);
    return XDP_DROP;
  }

  struct port_ban_key_v4 outbound = { .addr = iph->daddr, .port = dst_port };
  if (bpf_map_lookup_elem(&banned_ports_outbound_v4, &outbound)) {
    stats_inc_pkts_dropped();
    track_dropped_ipv4(iph->daddr);
    return XDP_DROP;
  }

  return XDP_PASS;
}
