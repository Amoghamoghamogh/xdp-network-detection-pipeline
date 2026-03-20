/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * maps.h — all BPF map definitions for the XDP pipeline.
 *
 * Naming convention:
 *   - IP ban maps:        banned_ipv4, banned_ipv6, recently_banned_ipv4/v6
 *   - Port ban maps:      banned_ports_inbound_v4/v6, banned_ports_outbound_v4/v6
 *   - Fingerprint maps:   tcp_fp_v4, tcp_fp_v6, tcp_fp_simple_v4/v6
 *   - Latency maps:       conn_latency_v4, conn_latency_v6
 *   - Stats maps:         stats_*
 */

#include "common.h"
#include "vmlinux.h"

/* ── Constants ─────────────────────────────────────────────────────────── */
#define TCP_FP_MAX_ENTRIES         10000
#define TCP_FP_MAX_OPTION_LEN      40
#define CONN_LATENCY_MAX_ENTRIES   10000
#define PORT_BAN_MAX_ENTRIES       4096
#define DROPPED_IP_TRACK_MAX       1000

/* ── Latency state machine ─────────────────────────────────────────────── */
#define LATENCY_STATE_SYN_SEEN    0
#define LATENCY_STATE_SYNACK_SEEN 1
#define LATENCY_STATE_COMPLETE    2

/* ── Key / value structs ───────────────────────────────────────────────── */

/* LPM trie key for IPv4 CIDR matching */
struct lpm_key_v4 {
  __u32 prefixlen;
  __be32 addr;
};

/* LPM trie key for IPv6 CIDR matching */
struct lpm_key_v6 {
  __u32 prefixlen;
  __u8  addr[16];
};

/* (IP, port) ban key — IPv4 */
struct port_ban_key_v4 {
  __be32 addr;
  __be16 port;
};

/* (IP, port) ban key — IPv6 */
struct port_ban_key_v6 {
  __u8   addr[16];
  __be16 port;
};

/* TCP fingerprint compound key — IPv4 */
struct tcp_fp_key_v4 {
  __be32 src_ip;
  __be16 src_port;
  __u8   fingerprint[14];
};

/* TCP fingerprint compound key — IPv6 */
struct tcp_fp_key_v6 {
  __u8   src_ip[16];
  __be16 src_port;
  __u8   fingerprint[14];
};

/* Simple (IP, port) key for O(1) userspace lookups — IPv4 */
struct __attribute__((packed)) tcp_fp_simple_key_v4 {
  __be32 src_ip;
  __be16 src_port;
  __u16  _pad;
};

/* Simple (IP, port) key for O(1) userspace lookups — IPv6 */
struct __attribute__((packed)) tcp_fp_simple_key_v6 {
  __u8   src_ip[16];
  __be16 src_port;
  __u16  _pad;
};

/* TCP fingerprint value */
struct tcp_fp_data {
  __u64 first_seen;
  __u64 last_seen;
  __u32 packet_count;
  __u16 ttl;
  __u16 mss;
  __u16 window_size;
  __u8  window_scale;
  __u8  options_len;
  __u8  options[TCP_FP_MAX_OPTION_LEN];
};

/* TCP SYN aggregate statistics */
struct tcp_syn_stats {
  __u64 total_syns;
  __u64 unique_fingerprints;
  __u64 last_reset;
};

/* Connection latency key — IPv4 */
struct __attribute__((packed)) conn_latency_key_v4 {
  __be32 client_ip;
  __be16 client_port;
  __u16  _pad;
};

/* Connection latency key — IPv6 */
struct __attribute__((packed)) conn_latency_key_v6 {
  __u8   client_ip[16];
  __be16 client_port;
  __u16  _pad;
};

/* Connection latency value */
struct conn_latency_data {
  __u64 syn_time_ns;
  __u64 synack_time_ns;
  __u64 ack_time_ns;
  __u8  client_ttl;
  __u8  server_ttl;
  __u8  state;
  __u8  _pad[5];
};

/* Latency aggregate statistics */
struct latency_stats_data {
  __u64 total_handshakes;
  __u64 complete_handshakes;
  __u64 total_packets;
  __u64 _reserved;
};

/* ── IP ban maps ───────────────────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v4);
  __type(value, ip_flag_t);
} banned_ipv4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v4);
  __type(value, ip_flag_t);
} recently_banned_ipv4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v6);
  __type(value, ip_flag_t);
} banned_ipv6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v6);
  __type(value, ip_flag_t);
} recently_banned_ipv6 SEC(".maps");

/* ── Port ban maps ─────────────────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PORT_BAN_MAX_ENTRIES);
  __type(key, struct port_ban_key_v4);
  __type(value, __u8);
} banned_ports_inbound_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PORT_BAN_MAX_ENTRIES);
  __type(key, struct port_ban_key_v6);
  __type(value, __u8);
} banned_ports_inbound_v6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PORT_BAN_MAX_ENTRIES);
  __type(key, struct port_ban_key_v4);
  __type(value, __u8);
} banned_ports_outbound_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, PORT_BAN_MAX_ENTRIES);
  __type(key, struct port_ban_key_v6);
  __type(value, __u8);
} banned_ports_outbound_v6 SEC(".maps");

/* ── TCP fingerprint maps ──────────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, struct tcp_fp_key_v4);
  __type(value, struct tcp_fp_data);
} tcp_fp_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, struct tcp_fp_key_v6);
  __type(value, struct tcp_fp_data);
} tcp_fp_v6 SEC(".maps");

/* Simple per-(IP, port) maps for O(1) userspace lookups */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, struct tcp_fp_simple_key_v4);
  __type(value, struct tcp_fp_data);
} tcp_fp_simple_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, struct tcp_fp_simple_key_v6);
  __type(value, struct tcp_fp_data);
} tcp_fp_simple_v6 SEC(".maps");

/* Blocked fingerprint sets */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, __u8[14]);
  __type(value, __u8);
} blocked_tcp_fp_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, TCP_FP_MAX_ENTRIES);
  __type(key, __u8[14]);
  __type(value, __u8);
} blocked_tcp_fp_v6 SEC(".maps");

/* ── Connection latency maps ───────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CONN_LATENCY_MAX_ENTRIES);
  __type(key, struct conn_latency_key_v4);
  __type(value, struct conn_latency_data);
} conn_latency_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CONN_LATENCY_MAX_ENTRIES);
  __type(key, struct conn_latency_key_v6);
  __type(value, struct conn_latency_data);
} conn_latency_v6 SEC(".maps");

/* ── Statistics maps ───────────────────────────────────────────────────── */

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_pkts_total SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_pkts_dropped SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_ipv4_banned SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_ipv4_recently_banned SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_ipv6_banned SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_ipv6_recently_banned SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_tcp_fp_blocks_v4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} stats_tcp_fp_blocks_v6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tcp_syn_stats);
} stats_tcp_syn SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct latency_stats_data);
} stats_latency SEC(".maps");

/* Per-IP drop counters */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, DROPPED_IP_TRACK_MAX);
  __type(key, __be32);
  __type(value, __u64);
} dropped_ipv4_counters SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, DROPPED_IP_TRACK_MAX);
  __type(key, __u8[16]);
  __type(value, __u64);
} dropped_ipv6_counters SEC(".maps");
