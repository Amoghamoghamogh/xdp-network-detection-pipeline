#pragma once

#include "common.h"
#include "../xdp_maps.h"
#include "helper.h"

/*
 * TCP handshake latency tracking for JA4L fingerprinting.
 *
 * XDP only sees inbound packets:
 *   - SYN (client -> server): record syn_time_ns, client_ttl
 *   - ACK (client -> server): record ack_time_ns, mark complete
 *
 * SYN-ACK is outbound (server -> client), not visible in XDP.
 * We approximate synack_time_ns = syn_time_ns since kernel responds
 * near-instantly. This gives accurate client RTT = (ACK - SYN).
 */

static __always_inline void increment_latency_handshakes(void) {
  __u32 key = 0;
  struct latency_stats_data *stats = bpf_map_lookup_elem(&latency_stats, &key);
  if (stats) {
    __sync_fetch_and_add(&stats->total_handshakes, 1);
  }
}

static __always_inline void increment_latency_complete(void) {
  __u32 key = 0;
  struct latency_stats_data *stats = bpf_map_lookup_elem(&latency_stats, &key);
  if (stats) {
    __sync_fetch_and_add(&stats->complete_handshakes, 1);
  }
}

static __always_inline void track_latency_v4(struct iphdr *iph,
                                              struct tcphdr *tcph,
                                              void *data_end) {
  if (!iph || !tcph)
    return;

  struct connection_latency_key_v4 key = {0};
  key.client_ip = iph->saddr;
  key.client_port = tcph->source;

  __u64 now = bpf_ktime_get_ns();

  if (tcph->syn && !tcph->ack) {
    // SYN packet: start tracking
    struct connection_latency_data data = {0};
    data.syn_time_ns = now;
    data.synack_time_ns = now; // Approximate: kernel responds near-instantly
    data.client_ttl = iph->ttl;
    data.server_ttl = 64; // Default server TTL (outbound SYN-ACK not visible)
    data.state = LATENCY_STATE_SYNACK_SEEN; // Skip to SYNACK since we approximate it
    bpf_map_update_elem(&connection_latency, &key, &data, BPF_NOEXIST);
    increment_latency_handshakes();
  } else if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
    // ACK packet: check if completing a handshake
    struct connection_latency_data *existing =
        bpf_map_lookup_elem(&connection_latency, &key);
    if (existing && existing->state == LATENCY_STATE_SYNACK_SEEN) {
      // Copy to local, update, write back
      struct connection_latency_data data = {0};
      data.syn_time_ns = existing->syn_time_ns;
      data.synack_time_ns = existing->synack_time_ns;
      data.ack_time_ns = now;
      data.client_ttl = existing->client_ttl;
      data.server_ttl = existing->server_ttl;
      data.state = LATENCY_STATE_COMPLETE;
      bpf_map_update_elem(&connection_latency, &key, &data, BPF_ANY);
      increment_latency_complete();
    }
  }
}

static __always_inline void track_latency_v6(struct ipv6hdr *ip6h,
                                              struct tcphdr *tcph,
                                              void *data_end) {
  if (!ip6h || !tcph)
    return;

  struct connection_latency_key_v6 key = {0};
  copy_ipv6_addr_as_array(&key.client_ip, &ip6h->saddr);
  key.client_port = tcph->source;

  __u64 now = bpf_ktime_get_ns();

  if (tcph->syn && !tcph->ack) {
    // SYN packet: start tracking
    struct connection_latency_data data = {0};
    data.syn_time_ns = now;
    data.synack_time_ns = now; // Approximate: kernel responds near-instantly
    data.client_ttl = ip6h->hop_limit;
    data.server_ttl = 64; // Default server TTL
    data.state = LATENCY_STATE_SYNACK_SEEN;
    bpf_map_update_elem(&connection_latency_v6, &key, &data, BPF_NOEXIST);
    increment_latency_handshakes();
  } else if (tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst) {
    // ACK packet: check if completing a handshake
    struct connection_latency_data *existing =
        bpf_map_lookup_elem(&connection_latency_v6, &key);
    if (existing && existing->state == LATENCY_STATE_SYNACK_SEEN) {
      struct connection_latency_data data = {0};
      data.syn_time_ns = existing->syn_time_ns;
      data.synack_time_ns = existing->synack_time_ns;
      data.ack_time_ns = now;
      data.client_ttl = existing->client_ttl;
      data.server_ttl = existing->server_ttl;
      data.state = LATENCY_STATE_COMPLETE;
      bpf_map_update_elem(&connection_latency_v6, &key, &data, BPF_ANY);
      increment_latency_complete();
    }
  }
}
