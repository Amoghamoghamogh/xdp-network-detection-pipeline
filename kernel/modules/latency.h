/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * modules/latency.h — TCP handshake latency tracking (JA4L-inspired).
 *
 * XDP only observes inbound packets, so the state machine is:
 *
 *   SYN  (client → server, inbound):  record syn_time_ns, client_ttl.
 *                                      synack_time_ns is approximated as
 *                                      syn_time_ns because the kernel
 *                                      responds near-instantly and the
 *                                      SYN-ACK is outbound (not visible).
 *   ACK  (client → server, inbound):  complete the record, compute RTT.
 *
 * The completed entry (state == LATENCY_STATE_COMPLETE) is readable from
 * userspace via the conn_latency_v4 / conn_latency_v6 maps.
 */

#include "../common.h"
#include "../maps.h"

/* ── Stat helpers ──────────────────────────────────────────────────────── */

static __always_inline void stats_inc_latency_handshakes(void) {
  __u32 key = 0;
  struct latency_stats_data *s = bpf_map_lookup_elem(&stats_latency, &key);
  if (s)
    __sync_fetch_and_add(&s->total_handshakes, 1);
}

static __always_inline void stats_inc_latency_complete(void) {
  __u32 key = 0;
  struct latency_stats_data *s = bpf_map_lookup_elem(&stats_latency, &key);
  if (s)
    __sync_fetch_and_add(&s->complete_handshakes, 1);
}

/* ── IPv4 latency tracking ─────────────────────────────────────────────── */

/**
 * track_latency_v4 - update connection latency state for an IPv4 TCP packet.
 */
static __always_inline void track_latency_v4(struct iphdr *iph,
                                             struct tcphdr *tcph,
                                             void *data_end) {
  if (!iph || !tcph)
    return;

  struct conn_latency_key_v4 key = {0};
  key.client_ip   = iph->saddr;
  key.client_port = tcph->source;

  __u64 now = bpf_ktime_get_ns();

  if (tcph->syn && !tcph->ack) {
    struct conn_latency_data entry = {0};
    entry.syn_time_ns    = now;
    entry.synack_time_ns = now; /* approximated — SYN-ACK is outbound */
    entry.client_ttl     = iph->ttl;
    entry.server_ttl     = 64;  /* default; SYN-ACK not visible at XDP */
    entry.state          = LATENCY_STATE_SYNACK_SEEN;
    bpf_map_update_elem(&conn_latency_v4, &key, &entry, BPF_NOEXIST);
    stats_inc_latency_handshakes();
  } else if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
    struct conn_latency_data *existing =
        bpf_map_lookup_elem(&conn_latency_v4, &key);
    if (existing && existing->state == LATENCY_STATE_SYNACK_SEEN) {
      struct conn_latency_data upd = {0};
      upd.syn_time_ns    = existing->syn_time_ns;
      upd.synack_time_ns = existing->synack_time_ns;
      upd.ack_time_ns    = now;
      upd.client_ttl     = existing->client_ttl;
      upd.server_ttl     = existing->server_ttl;
      upd.state          = LATENCY_STATE_COMPLETE;
      bpf_map_update_elem(&conn_latency_v4, &key, &upd, BPF_ANY);
      stats_inc_latency_complete();
    }
  }
}

/* ── IPv6 latency tracking ─────────────────────────────────────────────── */

/**
 * track_latency_v6 - update connection latency state for an IPv6 TCP packet.
 */
static __always_inline void track_latency_v6(struct ipv6hdr *ip6h,
                                             struct tcphdr *tcph,
                                             void *data_end) {
  if (!ip6h || !tcph)
    return;

  struct conn_latency_key_v6 key = {0};
  copy_ipv6_addr_as_array(key.client_ip, &ip6h->saddr);
  key.client_port = tcph->source;

  __u64 now = bpf_ktime_get_ns();

  if (tcph->syn && !tcph->ack) {
    struct conn_latency_data entry = {0};
    entry.syn_time_ns    = now;
    entry.synack_time_ns = now;
    entry.client_ttl     = ip6h->hop_limit;
    entry.server_ttl     = 64;
    entry.state          = LATENCY_STATE_SYNACK_SEEN;
    bpf_map_update_elem(&conn_latency_v6, &key, &entry, BPF_NOEXIST);
    stats_inc_latency_handshakes();
  } else if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
    struct conn_latency_data *existing =
        bpf_map_lookup_elem(&conn_latency_v6, &key);
    if (existing && existing->state == LATENCY_STATE_SYNACK_SEEN) {
      struct conn_latency_data upd = {0};
      upd.syn_time_ns    = existing->syn_time_ns;
      upd.synack_time_ns = existing->synack_time_ns;
      upd.ack_time_ns    = now;
      upd.client_ttl     = existing->client_ttl;
      upd.server_ttl     = existing->server_ttl;
      upd.state          = LATENCY_STATE_COMPLETE;
      bpf_map_update_elem(&conn_latency_v6, &key, &upd, BPF_ANY);
      stats_inc_latency_complete();
    }
  }
}
