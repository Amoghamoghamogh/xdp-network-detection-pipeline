#pragma once

#include "common.h"
#include "vmlinux.h"

#define TCP_FINGERPRINT_MAX_ENTRIES 10000

// IPv4 maps: permanently banned and recently banned
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key); // IPv4 address in network byte order
  __type(value, ip_flag_t);    // presence flag (1)
} banned_ips SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key);
  __type(value, ip_flag_t);
} recently_banned_ips SEC(".maps");

// IPv6 maps: permanently banned and recently banned
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v6);
  __type(value, ip_flag_t);
} banned_ips_v6 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __uint(max_entries, CITADEL_IP_MAP_MAX);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, struct lpm_key_v6);
  __type(value, ip_flag_t);
} recently_banned_ips_v6 SEC(".maps");

// Remove dynptr helpers, not used in XDP manual parsing
// extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
//                   struct bpf_dynptr *ptr__uninit) __ksym;
// extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, uint32_t offset,
//                   void *buffer, uint32_t buffer__sz) __ksym;

volatile int shootdowns = 0;

// Statistics maps for tracking access rule hits
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} ipv4_banned_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} ipv4_recently_banned_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} ipv6_banned_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} ipv6_recently_banned_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} total_packets_processed SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} total_packets_dropped SEC(".maps");

// Connection latency tracking (JA4L) - tracks TCP handshake SYN/SYNACK/ACK timestamps
#define LATENCY_STATE_SYN_SEEN 0
#define LATENCY_STATE_SYNACK_SEEN 1
#define LATENCY_STATE_COMPLETE 2
#define CONNECTION_LATENCY_MAX_ENTRIES 10000

// IPv4 key: client_ip(4) + client_port(2) + pad(2) = 8 bytes
// Client IP + ephemeral port is unique per connection, no server addr needed
struct __attribute__((packed)) connection_latency_key_v4 {
  __be32 client_ip;
  __be16 client_port;
  __u16 _pad;
};

// IPv6 key: client_ip(16) + client_port(2) + pad(2) = 20 bytes
struct __attribute__((packed)) connection_latency_key_v6 {
  __u8 client_ip[16];
  __be16 client_port;
  __u16 _pad;
};

// Value: timestamps + TTLs + state = 32 bytes (with padding)
struct connection_latency_data {
  __u64 syn_time_ns;
  __u64 synack_time_ns;
  __u64 ack_time_ns;
  __u8 client_ttl;
  __u8 server_ttl;
  __u8 state;
  __u8 _pad[5];
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CONNECTION_LATENCY_MAX_ENTRIES);
  __type(key, struct connection_latency_key_v4);
  __type(value, struct connection_latency_data);
} connection_latency SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CONNECTION_LATENCY_MAX_ENTRIES);
  __type(key, struct connection_latency_key_v6);
  __type(value, struct connection_latency_data);
} connection_latency_v6 SEC(".maps");

// Latency statistics (total handshakes, complete, packets)
struct latency_stats_data {
  __u64 total_handshakes;
  __u64 complete_handshakes;
  __u64 total_packets;
  __u64 _reserved;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct latency_stats_data);
} latency_stats SEC(".maps");

// TCP fingerprinting maps
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
  __type(key, struct tcp_fingerprint_key);
  __type(value, struct tcp_fingerprint_data);
} tcp_fingerprints SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
  __type(key, struct tcp_fingerprint_key_v6);
  __type(value, struct tcp_fingerprint_data);
} tcp_fingerprints_v6 SEC(".maps");

// JA4T direct-lookup maps: keyed by (IP, port) only for O(1) userspace lookups.
// The compound-key maps above are kept for per-fingerprint accounting; these
// simple maps mirror the latest fingerprint data for each (IP, port) pair.
// IPv4 key: src_ip(4) + src_port(2) + pad(2) = 8 bytes
struct __attribute__((packed)) tcp_fp_simple_key_v4 {
  __be32 src_ip;
  __be16 src_port;
  __u16 _pad;
};

// IPv6 key: src_ip(16) + src_port(2) + pad(2) = 20 bytes
struct __attribute__((packed)) tcp_fp_simple_key_v6 {
  __u8 src_ip[16];
  __be16 src_port;
  __u16 _pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
  __type(key, struct tcp_fp_simple_key_v4);
  __type(value, struct tcp_fingerprint_data);
} tcp_fingerprints_simple SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, TCP_FINGERPRINT_MAX_ENTRIES);
  __type(key, struct tcp_fp_simple_key_v6);
  __type(value, struct tcp_fingerprint_data);
} tcp_fingerprints_simple_v6 SEC(".maps");

// JA4TS SYN-ACK fingerprinting moved to separate TC BPF program (ja4ts.bpf.c)

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct tcp_syn_stats);
} tcp_syn_stats SEC(".maps");

// Blocked TCP fingerprint maps (only store the fingerprint string, not per-IP)
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000); // Store up to 10k blocked fingerprint patterns
  __type(key, __u8[14]);      // TCP fingerprint string (14 bytes)
  __type(value, __u8);        // Flag (1 = blocked)
} blocked_tcp_fingerprints SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, __u8[14]); // TCP fingerprint string (14 bytes)
  __type(value, __u8);   // Flag (1 = blocked)
} blocked_tcp_fingerprints_v6 SEC(".maps");

// Statistics for TCP fingerprint blocks
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} tcp_fingerprint_blocks_ipv4 SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} tcp_fingerprint_blocks_ipv6 SEC(".maps");

// Maps to track dropped IP addresses with counters
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1000); // Track up to 1000 unique dropped IPs
  __type(key, __be32);       // IPv4 address
  __type(value, __u64);      // Drop count
} dropped_ipv4_addresses SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1000); // Track up to 1000 unique dropped IPv6s
  __type(key, __u8[16]);     // IPv6 address
  __type(value, __u64);      // Drop count
} dropped_ipv6_addresses SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct src_port_key_v4);
  __type(value, __u8);
} banned_inbound_ipv4_address_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct src_port_key_v6);
  __type(value, __u8);
} banned_inbound_ipv6_address_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct src_port_key_v4);
  __type(value, __u8);
} banned_outbound_ipv4_address_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct src_port_key_v6);
  __type(value, __u8);
} banned_outbound_ipv6_address_ports SEC(".maps");
