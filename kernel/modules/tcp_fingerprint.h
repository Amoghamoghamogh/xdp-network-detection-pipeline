/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * modules/tcp_fingerprint.h — JA4T-style TCP SYN fingerprinting.
 *
 * On each inbound TCP SYN (not SYN-ACK) this module:
 *   1. Parses MSS and window-scale from TCP options (single pass).
 *   2. Builds a 14-byte fingerprint string: "TTT:MMMM:WWWWW".
 *   3. Checks the fingerprint against the blocked set → XDP_DROP if matched.
 *   4. Records the fingerprint in the compound and simple lookup maps.
 *
 * Design note: all option parsing is done once per packet to minimise the
 * BPF verifier instruction budget (avoids duplicate loop unrolling).
 */

#include "../common.h"
#include "../maps.h"
#include "firewall.h"  /* for stats_inc_* and track_dropped_* helpers */

/* ── Stat helpers ──────────────────────────────────────────────────────── */

static __always_inline void stats_inc_tcp_syn(void) {
  __u32 key = 0;
  struct tcp_syn_stats *s = bpf_map_lookup_elem(&stats_tcp_syn, &key);
  if (s)
    __sync_fetch_and_add(&s->total_syns, 1);
}

static __always_inline void stats_inc_unique_fp(void) {
  __u32 key = 0;
  struct tcp_syn_stats *s = bpf_map_lookup_elem(&stats_tcp_syn, &key);
  if (s)
    __sync_fetch_and_add(&s->unique_fingerprints, 1);
}

static __always_inline void stats_inc_fp_blocks_v4(void) {
  stats_inc_u64(&stats_tcp_fp_blocks_v4, 0);
}

static __always_inline void stats_inc_fp_blocks_v6(void) {
  stats_inc_u64(&stats_tcp_fp_blocks_v6, 0);
}

/* ── Option parsing ────────────────────────────────────────────────────── */

/**
 * parse_tcp_options - extract MSS and window-scale from TCP options.
 *
 * Uses a bounded loop (max 10 iterations) to stay within the verifier budget.
 * Covers all standard options: MSS(4B) + WScale(3B) + SACK_PERM(2B) +
 * Timestamps(10B) + NOPs.
 */
static __noinline void parse_tcp_options(struct tcphdr *tcp, void *data_end,
                                         __u16 *mss_out, __u8 *wscale_out) {
  if ((void *)tcp + sizeof(struct tcphdr) > data_end)
    return;

  __u8 *ptr = (__u8 *)tcp + sizeof(struct tcphdr);
  __u32 opts_len = (tcp->doff * 4) - sizeof(struct tcphdr);
  if (opts_len > 40)
    opts_len = 40;

  __u8 *end = ptr + opts_len;
  if (end > (__u8 *)data_end)
    end = (__u8 *)data_end;

  for (int i = 0; i < 10; i++) {
    if (ptr >= end || ptr + 1 > (__u8 *)data_end)
      break;

    __u8 kind = *ptr;
    if (kind == 0) break;   /* EOL */
    if (kind == 1) { ptr++; continue; } /* NOP */

    if (ptr + 2 > (__u8 *)data_end) break;
    __u8 len = *(ptr + 1);
    if (len < 2 || ptr + len > (__u8 *)data_end) break;

    if (kind == 2 && len == 4 && ptr + 4 <= (__u8 *)data_end)
      *mss_out = ((__u16)(*(ptr + 2)) << 8) | *(ptr + 3);
    else if (kind == 3 && len == 3 && ptr + 3 <= (__u8 *)data_end)
      *wscale_out = *(ptr + 2);

    ptr += len;
  }
}

/**
 * copy_tcp_options_raw - copy up to 20 raw option bytes for JA4T kind-list.
 *
 * Capped at 20 iterations to conserve verifier budget; covers all common
 * option combinations. The tcp_fp_data.options field is 40 bytes; unused
 * bytes remain zeroed.
 */
static __noinline void copy_tcp_options_raw(struct tcphdr *tcp, void *data_end,
                                            __u8 *out, __u8 *out_len) {
  *out_len = 0;
  if ((void *)tcp + sizeof(struct tcphdr) > data_end)
    return;

  __u32 total = (tcp->doff * 4) - sizeof(struct tcphdr);
  if (total > 20) total = 20;

  __u8 *src = (__u8 *)tcp + sizeof(struct tcphdr);
  if (src + total > (__u8 *)data_end)
    total = (__u8 *)data_end - src;
  if (total > 20) total = 20;

  *out_len = (__u8)total;
  for (int i = 0; i < 20; i++) {
    if (i >= (int)total || src + i + 1 > (__u8 *)data_end) break;
    out[i] = src[i];
  }
}

/* ── Fingerprint generation ────────────────────────────────────────────── */

/**
 * build_fingerprint - encode TTL, MSS, and window into a 14-byte ASCII string.
 *
 * Format: "TTT:MMMM:WWWWW"  (no null terminator — fixed 14 bytes)
 * Window scale is omitted to fit within the 14-byte budget.
 */
static __always_inline void build_fingerprint(__u16 ttl, __u16 mss,
                                              __u16 window, __u8 fp[14]) {
  fp[0]  = '0' + (ttl / 100);
  fp[1]  = '0' + ((ttl / 10) % 10);
  fp[2]  = '0' + (ttl % 10);
  fp[3]  = ':';
  fp[4]  = '0' + (mss / 1000);
  fp[5]  = '0' + ((mss / 100) % 10);
  fp[6]  = '0' + ((mss / 10) % 10);
  fp[7]  = '0' + (mss % 10);
  fp[8]  = ':';
  fp[9]  = '0' + (window / 10000);
  fp[10] = '0' + ((window / 1000) % 10);
  fp[11] = '0' + ((window / 100) % 10);
  fp[12] = '0' + ((window / 10) % 10);
  fp[13] = '0' + (window % 10);
}

/* ── Block-list checks ─────────────────────────────────────────────────── */

static __always_inline bool fp_is_blocked_v4(__u8 fp[14]) {
  __u8 *v = bpf_map_lookup_elem(&blocked_tcp_fp_v4, fp);
  return (v && *v == 1);
}

static __always_inline bool fp_is_blocked_v6(__u8 fp[14]) {
  __u8 *v = bpf_map_lookup_elem(&blocked_tcp_fp_v6, fp);
  return (v && *v == 1);
}

/* ── Main entry point ──────────────────────────────────────────────────── */

/**
 * xdp_tcp_fingerprint - process a TCP SYN and update fingerprint state.
 *
 * Must be called only for TCP packets; the SYN/ACK guard is internal.
 * Returns XDP_DROP if the fingerprint is on the block list, XDP_PASS otherwise.
 */
static __noinline int xdp_tcp_fingerprint(struct xdp_md *ctx,
                                          struct iphdr *iph,
                                          struct ipv6hdr *ip6h,
                                          struct tcphdr *tcph) {
  if (!tcph || !tcph->syn || tcph->ack)
    return XDP_PASS;

  void *data_end = (void *)(long)ctx->data_end;
  if ((void *)tcph + sizeof(struct tcphdr) > data_end)
    return XDP_PASS;

  stats_inc_tcp_syn();

  /* Parse options once */
  __u16 mss = 0;
  __u8  wscale = 0;
  parse_tcp_options(tcph, data_end, &mss, &wscale);

  __u16 ttl    = iph ? iph->ttl : (ip6h ? ip6h->hop_limit : 0);
  __u16 window = bpf_ntohs(tcph->window);

  __u8 fp[14] = {0};
  build_fingerprint(ttl, mss, window, fp);

  __u64 now = bpf_ktime_get_ns();

  /* ── IPv4 path ── */
  if (iph) {
    if (fp_is_blocked_v4(fp)) {
      stats_inc_fp_blocks_v4();
      stats_inc_pkts_dropped();
      track_dropped_ipv4(iph->saddr);
      return XDP_DROP;
    }

    /* Skip loopback */
    if ((iph->saddr & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000))
      return XDP_PASS;

    struct tcp_fp_key_v4 key = {0};
    key.src_ip   = iph->saddr;
    key.src_port = tcph->source;
    __builtin_memcpy(key.fingerprint, fp, 14);

    struct tcp_fp_data *existing = bpf_map_lookup_elem(&tcp_fp_v4, &key);
    if (existing) {
      struct tcp_fp_data upd = {0};
      upd.first_seen   = existing->first_seen;
      upd.last_seen    = now;
      upd.packet_count = existing->packet_count + 1;
      upd.ttl          = existing->ttl;
      upd.mss          = existing->mss;
      upd.window_size  = existing->window_size;
      upd.window_scale = existing->window_scale;
      upd.options_len  = existing->options_len;
      __builtin_memcpy(upd.options, existing->options, TCP_FP_MAX_OPTION_LEN);
      bpf_map_update_elem(&tcp_fp_v4, &key, &upd, BPF_ANY);
    } else {
      struct tcp_fp_data new_entry = {0};
      new_entry.first_seen   = now;
      new_entry.last_seen    = now;
      new_entry.packet_count = 1;
      new_entry.ttl          = ttl;
      new_entry.mss          = mss;
      new_entry.window_size  = window;
      new_entry.window_scale = wscale;
      copy_tcp_options_raw(tcph, data_end, new_entry.options,
                           &new_entry.options_len);
      bpf_map_update_elem(&tcp_fp_v4, &key, &new_entry, BPF_ANY);
      stats_inc_unique_fp();
    }

    /* Mirror into simple (IP, port) map for userspace */
    struct tcp_fp_simple_key_v4 skey = {0};
    skey.src_ip   = iph->saddr;
    skey.src_port = tcph->source;
    struct tcp_fp_data *latest = bpf_map_lookup_elem(&tcp_fp_v4, &key);
    if (latest)
      bpf_map_update_elem(&tcp_fp_simple_v4, &skey, latest, BPF_ANY);
  }
  /* ── IPv6 path ── */
  else if (ip6h) {
    if (fp_is_blocked_v6(fp)) {
      stats_inc_fp_blocks_v6();
      stats_inc_pkts_dropped();
      track_dropped_ipv6(ip6h->saddr);
      return XDP_DROP;
    }

    struct tcp_fp_key_v6 key = {0};
    copy_ipv6_addr_as_array(key.src_ip, &ip6h->saddr);
    key.src_port = tcph->source;
    __builtin_memcpy(key.fingerprint, fp, 14);

    struct tcp_fp_data *existing = bpf_map_lookup_elem(&tcp_fp_v6, &key);
    if (existing) {
      struct tcp_fp_data upd = {0};
      upd.first_seen   = existing->first_seen;
      upd.last_seen    = now;
      upd.packet_count = existing->packet_count + 1;
      upd.ttl          = existing->ttl;
      upd.mss          = existing->mss;
      upd.window_size  = existing->window_size;
      upd.window_scale = existing->window_scale;
      upd.options_len  = existing->options_len;
      __builtin_memcpy(upd.options, existing->options, TCP_FP_MAX_OPTION_LEN);
      bpf_map_update_elem(&tcp_fp_v6, &key, &upd, BPF_ANY);
    } else {
      struct tcp_fp_data new_entry = {0};
      new_entry.first_seen   = now;
      new_entry.last_seen    = now;
      new_entry.packet_count = 1;
      new_entry.ttl          = ip6h->hop_limit;
      new_entry.mss          = mss;
      new_entry.window_size  = window;
      new_entry.window_scale = wscale;
      copy_tcp_options_raw(tcph, data_end, new_entry.options,
                           &new_entry.options_len);
      bpf_map_update_elem(&tcp_fp_v6, &key, &new_entry, BPF_ANY);
      stats_inc_unique_fp();
    }

    /* Mirror into simple (IP, port) map for userspace */
    struct tcp_fp_simple_key_v6 skey = {0};
    copy_ipv6_addr_as_array(skey.src_ip, &ip6h->saddr);
    skey.src_port = tcph->source;
    struct tcp_fp_data *latest = bpf_map_lookup_elem(&tcp_fp_v6, &key);
    if (latest)
      bpf_map_update_elem(&tcp_fp_simple_v6, &skey, latest, BPF_ANY);
  }

  return XDP_PASS;
}
