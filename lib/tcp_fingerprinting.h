#pragma once

#include "common.h"

#include "../xdp_maps.h"
#include "firewall.h"
#include "helper.h"

// TCP fingerprinting constants

#define TCP_FP_KEY_SIZE 20 // 4 bytes IP + 2 bytes port + 14 bytes fingerprint
#define TCP_FP_MAX_OPTIONS 10
#define TCP_FP_MAX_OPTION_LEN 40

// TCP fingerprinting structures
struct tcp_fingerprint_key {
  __be32 src_ip;        // Source IP address (IPv4)
  __be16 src_port;      // Source port
  __u8 fingerprint[14]; // TCP fingerprint string (null-terminated)
};

struct tcp_fingerprint_key_v6 {
  __u8 src_ip[16];      // Source IP address (IPv6)
  __be16 src_port;      // Source port
  __u8 fingerprint[14]; // TCP fingerprint string (null-terminated)
};

struct tcp_fingerprint_data {
  __u64 first_seen;                    // Timestamp of first packet
  __u64 last_seen;                     // Timestamp of last packet
  __u32 packet_count;                  // Number of packets seen
  __u16 ttl;                           // Initial TTL
  __u16 mss;                           // Maximum Segment Size
  __u16 window_size;                   // TCP window size
  __u8 window_scale;                   // Window scaling factor
  __u8 options_len;                    // Length of TCP options
  __u8 options[TCP_FP_MAX_OPTION_LEN]; // TCP options data
};

struct tcp_syn_stats {
  __u64 total_syns;
  __u64 unique_fingerprints;
  __u64 last_reset;
};

/*
 * TCP fingerprinting helper functions
 */
static __always_inline void increment_tcp_syn_stats(void) {
  __u32 key = 0;
  struct tcp_syn_stats *stats = bpf_map_lookup_elem(&tcp_syn_stats, &key);
  if (stats) {
    __sync_fetch_and_add(&stats->total_syns, 1);
  } else {
    struct tcp_syn_stats new_stats = {0};
    new_stats.total_syns = 1;
    bpf_map_update_elem(&tcp_syn_stats, &key, &new_stats, BPF_ANY);
  }
}

static __always_inline void increment_unique_fingerprints(void) {
  __u32 key = 0;
  struct tcp_syn_stats *stats = bpf_map_lookup_elem(&tcp_syn_stats, &key);
  if (stats) {
    __sync_fetch_and_add(&stats->unique_fingerprints, 1);
  }
}

static __always_inline void increment_tcp_fingerprint_blocks_ipv4(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&tcp_fingerprint_blocks_ipv4, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_tcp_fingerprint_blocks_ipv6(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&tcp_fingerprint_blocks_ipv6, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __noinline int parse_tcp_mss_wscale(struct tcphdr *tcp,
                                           void *data_end, __u16 *mss_out,
                                           __u8 *wscale_out) {
  if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
    return 0;
  }

  __u8 *ptr = (__u8 *)tcp + sizeof(struct tcphdr);
  __u32 options_len = (tcp->doff * 4) - sizeof(struct tcphdr);

  // Guard against invalid doff
  if (options_len > 40) { // Max TCP options length
    options_len = 40;
  }

  __u8 *end = ptr + options_len;

  // Ensure we don't exceed packet bounds
  if (end > (__u8 *)data_end) {
    end = (__u8 *)data_end;
  }

  // Safety check
  if (ptr >= end) {
    return 0;
  }

// Parse options — limit to 10 iterations (enough for all standard TCP options:
// MSS(4B) + WScale(3B) + SACK_PERM(2B) + Timestamps(10B) + NOPs = ~8 iterations max)
// No #pragma unroll — use bounded loop (Linux 5.3+) to reduce verifier state explosion
  for (int i = 0; i < 10; i++) {
    if (ptr >= end || ptr >= (__u8 *)data_end)
      break;
    if (ptr + 1 > (__u8 *)data_end)
      break;

    __u8 kind = *ptr;
    if (kind == 0)
      break; // End of options

    if (kind == 1) {
      // NOP option
      ptr++;
      continue;
    }

    // Check bounds for option length
    if (ptr + 2 > (__u8 *)data_end)
      break;
    __u8 len = *(ptr + 1);
    if (len < 2 || ptr + len > (__u8 *)data_end)
      break;

    // MSS option (kind=2, len=4)
    if (kind == 2 && len == 4 && ptr + 4 <= (__u8 *)data_end) {
      *mss_out = (*(ptr + 2) << 8) | *(ptr + 3);
    }
    // Window scale option (kind=3, len=3)
    else if (kind == 3 && len == 3 && ptr + 3 <= (__u8 *)data_end) {
      *wscale_out = *(ptr + 2);
    }

    ptr += len;
  }

  return 0;
}

/// Copy raw TCP options bytes into a buffer for JA4T option-kind extraction.
/// Sets *out_len to the number of bytes actually copied (up to
/// TCP_FP_MAX_OPTION_LEN).
static __noinline void copy_raw_tcp_options(struct tcphdr *tcp,
                                                  void *data_end,
                                                  __u8 *options_out,
                                                  __u8 *out_len) {
  *out_len = 0;

  if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
    return;
  }

  __u32 opt_total = (tcp->doff * 4) - sizeof(struct tcphdr);
  if (opt_total > TCP_FP_MAX_OPTION_LEN) {
    opt_total = TCP_FP_MAX_OPTION_LEN;
  }

  __u8 *src = (__u8 *)tcp + sizeof(struct tcphdr);
  if (src + opt_total > (__u8 *)data_end) {
    opt_total = (__u8 *)data_end - src;
    if (opt_total > TCP_FP_MAX_OPTION_LEN) {
      opt_total = TCP_FP_MAX_OPTION_LEN;
    }
  }

  *out_len = (__u8)opt_total;

// No #pragma unroll — use bounded loop (Linux 5.3+) to reduce verifier state explosion
  for (int i = 0; i < 20; i++) {
    if (i >= (int)opt_total || src + i + 1 > (__u8 *)data_end)
      break;
    options_out[i] = src[i];
  }
}

static __always_inline void generate_tcp_fingerprint(struct tcphdr *tcp,
                                                     void *data_end, __u16 ttl,
                                                     __u8 *fingerprint) {
  // Generate JA4T-style fingerprint: ttl:mss:window:scale
  __u16 mss = 0;
  __u8 window_scale = 0;

  if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
    return;
  }

  // Parse TCP options to extract MSS and window scaling
  parse_tcp_mss_wscale(tcp, data_end, &mss, &window_scale);

  // Generate fingerprint string manually (BPF doesn't support complex
  // formatting)
  __u16 window = bpf_ntohs(tcp->window);

  // Format: "ttl:mss:window:scale" (max 14 chars)
  fingerprint[0] = '0' + (ttl / 100);
  fingerprint[1] = '0' + ((ttl / 10) % 10);
  fingerprint[2] = '0' + (ttl % 10);
  fingerprint[3] = ':';
  fingerprint[4] = '0' + (mss / 1000);
  fingerprint[5] = '0' + ((mss / 100) % 10);
  fingerprint[6] = '0' + ((mss / 10) % 10);
  fingerprint[7] = '0' + (mss % 10);
  fingerprint[8] = ':';
  fingerprint[9] = '0' + (window / 10000);
  fingerprint[10] = '0' + ((window / 1000) % 10);
  fingerprint[11] = '0' + ((window / 100) % 10);
  fingerprint[12] = '0' + ((window / 10) % 10);
  fingerprint[13] = '0' + (window % 10);
  // Note: window_scale is not included due to space constraints
}

/*
 * Check if a TCP fingerprint is blocked (IPv4)
 * Returns true if the fingerprint should be blocked
 */
static __always_inline bool is_tcp_fingerprint_blocked(__u8 *fingerprint) {
  __u8 *blocked = bpf_map_lookup_elem(&blocked_tcp_fingerprints, fingerprint);
  return (blocked != NULL && *blocked == 1);
}

/*
 * Check if a TCP fingerprint is blocked (IPv6)
 * Returns true if the fingerprint should be blocked
 */
static __always_inline bool is_tcp_fingerprint_blocked_v6(__u8 *fingerprint) {
  __u8 *blocked =
      bpf_map_lookup_elem(&blocked_tcp_fingerprints_v6, fingerprint);
  return (blocked != NULL && *blocked == 1);
}

static __always_inline void record_tcp_fingerprint(__be32 src_ip,
                                                   __be16 src_port,
                                                   struct tcphdr *tcp,
                                                   void *data_end, __u16 ttl) {
  // Skip localhost traffic to reduce noise
  // Check for 127.0.0.0/8 range (127.0.0.1 to 127.255.255.255)
  if ((src_ip & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000)) {
    return;
  }

  struct tcp_fingerprint_key key = {0};
  struct tcp_fingerprint_data data = {0};
  __u64 timestamp = bpf_ktime_get_ns();

  key.src_ip = src_ip;
  key.src_port = src_port;

  // Generate fingerprint
  generate_tcp_fingerprint(tcp, data_end, ttl, key.fingerprint);

  // Check if fingerprint already exists
  struct tcp_fingerprint_data *existing =
      bpf_map_lookup_elem(&tcp_fingerprints, &key);
  if (existing) {
    // Update existing entry - must copy to local variable first
    data.first_seen = existing->first_seen;
    data.last_seen = timestamp;
    data.packet_count = existing->packet_count + 1;
    data.ttl = existing->ttl;
    data.mss = existing->mss;
    data.window_size = existing->window_size;
    data.window_scale = existing->window_scale;
    data.options_len = existing->options_len;

    // Copy options array
    __builtin_memcpy(data.options, existing->options, TCP_FP_MAX_OPTION_LEN);

    bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
  } else {
    // Create new entry
    data.first_seen = timestamp;
    data.last_seen = timestamp;
    data.packet_count = 1;
    data.ttl = ttl;
    data.window_size = bpf_ntohs(tcp->window);

    // Extract MSS and window scale from options
    parse_tcp_mss_wscale(tcp, data_end, &data.mss, &data.window_scale);

    // Copy raw TCP options for JA4T option-kind fingerprinting
    copy_raw_tcp_options(tcp, data_end, data.options, &data.options_len);

    bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
    increment_unique_fingerprints();
  }

  // Also populate the simple (IP, port) map for O(1) userspace lookups.
  struct tcp_fp_simple_key_v4 skey = {0};
  skey.src_ip = src_ip;
  skey.src_port = src_port;
  bpf_map_update_elem(&tcp_fingerprints_simple, &skey, &data, BPF_ANY);
}


/// Copy raw TCP options bytes (reduced to 20 iterations for verifier budget).
/// Covers all standard TCP options (MSS, SACK, timestamps, window scale, NOP).
/// The struct options field stays 40 bytes; unused bytes remain zeroed.
static __noinline void copy_raw_tcp_options_short(struct tcphdr *tcp,
                                                        void *data_end,
                                                        __u8 *options_out,
                                                        __u8 *out_len) {
  *out_len = 0;
  if ((void *)tcp + sizeof(struct tcphdr) > data_end)
    return;

  __u32 opt_total = (tcp->doff * 4) - sizeof(struct tcphdr);
  if (opt_total > 20)
    opt_total = 20;

  __u8 *src = (__u8 *)tcp + sizeof(struct tcphdr);
  if (src + opt_total > (__u8 *)data_end) {
    opt_total = (__u8 *)data_end - src;
    if (opt_total > 20)
      opt_total = 20;
  }

  *out_len = (__u8)opt_total;

  for (int i = 0; i < 20; i++) {
    if (i >= (int)opt_total || src + i + 1 > (__u8 *)data_end)
      break;
    options_out[i] = src[i];
  }
}

/// Refactored: computes everything ONCE to minimize verifier state explosion.
///
/// Previous version inlined 4 loops (~100 iterations total):
///   generate_tcp_fingerprint -> parse_tcp_mss_wscale (20 iters)  [1st]
///   record_tcp_fingerprint   -> generate_tcp_fingerprint (20 iters) [2nd - DUPLICATE]
///   record_tcp_fingerprint   -> parse_tcp_mss_wscale (20 iters)  [3rd - TRIPLICATE]
///   record_tcp_fingerprint   -> copy_raw_tcp_options (40 iters)
///
/// Now: 1x parse_tcp_mss_wscale (20 iters) + 1x copy_raw_tcp_options_short (20 iters)
///      = 40 iterations total (~60% reduction in verifier states)
static __noinline int xdp_tcp_fingerprinting(struct xdp_md *ctx,
                                             struct iphdr *iph,
                                             struct ipv6hdr *ip6h,
                                             struct tcphdr *tcph) {
  if (!tcph || !tcph->syn || tcph->ack)
    return XDP_PASS;

  void *data_end = (void *)(long)ctx->data_end;
  if ((void *)tcph + sizeof(struct tcphdr) > data_end)
    return XDP_PASS;

  increment_tcp_syn_stats();

  // --- Parse MSS + window scale ONCE (single 20-iteration loop) ---
  __u16 mss = 0;
  __u8 wscale = 0;
  parse_tcp_mss_wscale(tcph, data_end, &mss, &wscale);

  // --- Build fingerprint string ONCE (pure arithmetic, no loops) ---
  __u16 ttl = iph ? iph->ttl : (ip6h ? ip6h->hop_limit : 0);
  __u16 window = bpf_ntohs(tcph->window);
  __u8 fingerprint[14] = {0};
  fingerprint[0] = '0' + (ttl / 100);
  fingerprint[1] = '0' + ((ttl / 10) % 10);
  fingerprint[2] = '0' + (ttl % 10);
  fingerprint[3] = ':';
  fingerprint[4] = '0' + (mss / 1000);
  fingerprint[5] = '0' + ((mss / 100) % 10);
  fingerprint[6] = '0' + ((mss / 10) % 10);
  fingerprint[7] = '0' + (mss % 10);
  fingerprint[8] = ':';
  fingerprint[9] = '0' + (window / 10000);
  fingerprint[10] = '0' + ((window / 1000) % 10);
  fingerprint[11] = '0' + ((window / 100) % 10);
  fingerprint[12] = '0' + ((window / 10) % 10);
  fingerprint[13] = '0' + (window % 10);

  // --- IPv4 path ---
  if (iph) {
    if (is_tcp_fingerprint_blocked(fingerprint)) {
      increment_tcp_fingerprint_blocks_ipv4();
      increment_total_packets_dropped();
      increment_dropped_ipv4_address(iph->saddr);
      return XDP_DROP;
    }

    // Skip localhost
    if ((iph->saddr & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000))
      return XDP_PASS;

    struct tcp_fingerprint_key key = {0};
    key.src_ip = iph->saddr;
    key.src_port = tcph->source;
    __builtin_memcpy(key.fingerprint, fingerprint, 14);

    __u64 now = bpf_ktime_get_ns();
    struct tcp_fingerprint_data *existing =
        bpf_map_lookup_elem(&tcp_fingerprints, &key);
    if (existing) {
      struct tcp_fingerprint_data data = {0};
      data.first_seen = existing->first_seen;
      data.last_seen = now;
      data.packet_count = existing->packet_count + 1;
      data.ttl = existing->ttl;
      data.mss = existing->mss;
      data.window_size = existing->window_size;
      data.window_scale = existing->window_scale;
      data.options_len = existing->options_len;
      __builtin_memcpy(data.options, existing->options, TCP_FP_MAX_OPTION_LEN);
      bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
    } else {
      struct tcp_fingerprint_data data = {0};
      data.first_seen = now;
      data.last_seen = now;
      data.packet_count = 1;
      data.ttl = ttl;
      data.mss = mss;             // Already parsed above
      data.window_size = window;
      data.window_scale = wscale;  // Already parsed above
      copy_raw_tcp_options_short(tcph, data_end, data.options,
                                 &data.options_len);
      bpf_map_update_elem(&tcp_fingerprints, &key, &data, BPF_ANY);
      increment_unique_fingerprints();
    }

    // Populate simple (IP, port) map for O(1) userspace lookups
    {
      struct tcp_fp_simple_key_v4 skey = {0};
      skey.src_ip = iph->saddr;
      skey.src_port = tcph->source;
      struct tcp_fingerprint_data *latest =
          bpf_map_lookup_elem(&tcp_fingerprints, &key);
      if (latest) {
        bpf_map_update_elem(&tcp_fingerprints_simple, &skey, latest, BPF_ANY);
      }
    }
  }
  // --- IPv6 path ---
  else if (ip6h) {
    if (is_tcp_fingerprint_blocked_v6(fingerprint)) {
      increment_tcp_fingerprint_blocks_ipv6();
      increment_total_packets_dropped();
      increment_dropped_ipv6_address(ip6h->saddr);
      return XDP_DROP;
    }

    struct tcp_fingerprint_key_v6 key = {0};
    copy_ipv6_addr_as_array(&key.src_ip, &ip6h->saddr);
    key.src_port = tcph->source;
    __builtin_memcpy(key.fingerprint, fingerprint, 14);

    __u64 now = bpf_ktime_get_ns();
    struct tcp_fingerprint_data *existing =
        bpf_map_lookup_elem(&tcp_fingerprints_v6, &key);
    if (existing) {
      struct tcp_fingerprint_data data = {0};
      data.first_seen = existing->first_seen;
      data.last_seen = now;
      data.packet_count = existing->packet_count + 1;
      data.ttl = existing->ttl;
      data.mss = existing->mss;
      data.window_size = existing->window_size;
      data.window_scale = existing->window_scale;
      data.options_len = existing->options_len;
      __builtin_memcpy(data.options, existing->options, TCP_FP_MAX_OPTION_LEN);
      bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
    } else {
      struct tcp_fingerprint_data data = {0};
      data.first_seen = now;
      data.last_seen = now;
      data.packet_count = 1;
      data.ttl = ip6h->hop_limit;
      data.mss = mss;
      data.window_size = window;
      data.window_scale = wscale;
      copy_raw_tcp_options_short(tcph, data_end, data.options,
                                 &data.options_len);
      bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
      increment_unique_fingerprints();
    }

    // Populate simple (IP, port) map for O(1) userspace lookups
    {
      struct tcp_fp_simple_key_v6 skey = {0};
      copy_ipv6_addr_as_array(&skey.src_ip, &ip6h->saddr);
      skey.src_port = tcph->source;
      struct tcp_fingerprint_data *latest =
          bpf_map_lookup_elem(&tcp_fingerprints_v6, &key);
      if (latest) {
        bpf_map_update_elem(&tcp_fingerprints_simple_v6, &skey, latest,
                            BPF_ANY);
      }
    }
  }

  return XDP_PASS;
}
