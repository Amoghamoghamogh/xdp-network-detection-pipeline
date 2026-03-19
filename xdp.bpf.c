#include "common.h"

#include "lib/firewall.h"
#include "lib/helper.h"
#include "lib/tcp_fingerprinting.h"
#include "lib/latency_tracking.h"
#include "vmlinux.h"
#include "xdp_maps.h"

SEC("xdp")
int xdp_pipeline(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *cursor = (void *)(long)ctx->data;

  // Debug: Count all packets
  __u32 zero = 0;
  __u32 *packet_count = bpf_map_lookup_elem(&total_packets_processed, &zero);
  if (packet_count) {
    __sync_fetch_and_add(packet_count, 1);
  }

  struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
  if (!eth) {
    return XDP_PASS;
  }

  struct iphdr *iph = NULL;
  struct ipv6hdr *ip6h = NULL;
  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
    if (!iph) {
      return XDP_PASS;
    }

  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = parse_and_advance(&cursor, data_end, sizeof(*ip6h));
    if (!ip6h) {
      return XDP_PASS;
    }
  }

  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;
  if ((ip6h && ip6h->nexthdr == IPPROTO_UDP) ||
      (iph && iph->protocol == IPPROTO_UDP)) {
    udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
    if (!udph) {
      return XDP_PASS;
    }
  } else if ((ip6h && ip6h->nexthdr == IPPROTO_TCP) ||
             (iph && iph->protocol == IPPROTO_TCP)) {
    tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
    if (!tcph) {
      return XDP_PASS;
    }
  }

  if (xdp_firewall(iph, ip6h) == XDP_DROP)
    return XDP_DROP;

  if (xdp_portban(iph, tcph, udph) == XDP_DROP)
    return XDP_DROP;

  if (xdp_tcp_fingerprinting(ctx, iph, ip6h, tcph) == XDP_DROP)
    return XDP_DROP;

  // JA4TS SYN-ACK capture moved to separate TC BPF program (ja4ts.bpf.c)

  // Track TCP handshake latency for JA4L fingerprinting
  if (tcph) {
    if (iph)
      track_latency_v4(iph, tcph, data_end);
    else if (ip6h)
      track_latency_v6(ip6h, tcph, data_end);
  }

  increment_total_packets_processed();

  return XDP_PASS;
}

// SEC("xdp")
// int arxignis_xdp_filter(struct xdp_md *ctx) {
//   // This filter is designed to only block incoming traffic
//   // It should be attached only to ingress hooks, not egress
//   // The filtering logic below blocks packets based on source IP addresses
//   //
//   // IP Version Support:
//   // - Supports IPv4-only, IPv6-only, and hybrid (both) modes
//   // - Note: XDP requires IPv6 to be enabled at kernel level for attachment,
//   //   even when processing only IPv4 packets. This is a kernel limitation.
//   // - The BPF program processes both IPv4 and IPv6 packets based on the
//   //   ethernet protocol type (ETH_P_IP for IPv4, ETH_P_IPV6 for IPv6)

//   void *data_end = (void *)(long)ctx->data_end;
//   void *cursor = (void *)(long)ctx->data;

//   // Debug: Count all packets
//   __u32 zero = 0;
//   __u32 *packet_count = bpf_map_lookup_elem(&total_packets_processed, &zero);
//   if (packet_count) {
//     __sync_fetch_and_add(packet_count, 1);
//   }

//   struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
//   if (!eth)
//     return XDP_PASS;

//   __u16 h_proto = eth->h_proto;

//   // Increment total packets processed counter
//   increment_total_packets_processed();

//   if (h_proto == bpf_htons(ETH_P_IP)) {
//     struct iphdr *iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
//     if (!iph)
//       return XDP_PASS;

//     struct lpm_key key = {
//         .prefixlen = 32,
//         .addr = iph->saddr,
//     };

//     if (bpf_map_lookup_elem(&banned_ips, &key)) {
//       increment_ipv4_banned_stats();
//       increment_total_packets_dropped();
//       increment_dropped_ipv4_address(iph->saddr);
//       // bpf_printk("XDP: BLOCKED incoming permanently banned IPv4 %pI4",
//       // &iph->saddr);
//       return XDP_DROP;
//     }

//     if (bpf_map_lookup_elem(&recently_banned_ips, &key)) {
//       increment_ipv4_recently_banned_stats();
//       // Block UDP and ICMP from recently banned IPs, but allow DNS
//       if (iph->protocol == IPPROTO_UDP) {
//         struct udphdr *udph =
//             parse_and_advance(&cursor, data_end, sizeof(*udph));
//         if (udph && udph->dest == bpf_htons(53)) {
//           return XDP_PASS; // Allow DNS responses
//         }
//         // Block other UDP traffic
//         ip_flag_t one = 1;
//         bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
//         bpf_map_delete_elem(&recently_banned_ips, &key);
//         increment_total_packets_dropped();
//         increment_dropped_ipv4_address(iph->saddr);
//         // bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv4
//         %pI4,
//         // promoted to permanent ban", &iph->saddr);
//         return XDP_DROP;
//       }
//       if (iph->protocol == IPPROTO_ICMP) {
//         ip_flag_t one = 1;
//         bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
//         bpf_map_delete_elem(&recently_banned_ips, &key);
//         increment_total_packets_dropped();
//         increment_dropped_ipv4_address(iph->saddr);
//         // bpf_printk("XDP: BLOCKED incoming ICMP from recently banned IPv4
//         // %pI4, promoted to permanent ban", &iph->saddr);
//         return XDP_DROP;
//       }
//       // For TCP, only promote to banned on FIN/RST
//       if (iph->protocol == IPPROTO_TCP) {
//         bpf_printk("tcp asd");
//         struct tcphdr *tcph =
//             parse_and_advance(&cursor, data_end, sizeof(*tcph));
//         if (tcph) {
//           // Perform TCP fingerprinting ONLY on SYN packets (not SYN-ACK)
//           // This ensures we capture the initial handshake with MSS/WSCALE
//           if (tcph->syn && !tcph->ack) {
//             increment_tcp_syn_stats();

//             if (ipv4_syn_ratelimit(iph->saddr) == XDP_DROP) {
//               return XDP_DROP;
//             }

//             // Generate fingerprint to check if blocked
//             __u8 fingerprint[14] = {0};
//             generate_tcp_fingerprint(tcph, data_end, iph->ttl, fingerprint);

//             // Check if this TCP fingerprint is blocked
//             if (is_tcp_fingerprint_blocked(fingerprint)) {
//               increment_tcp_fingerprint_blocks_ipv4();
//               increment_total_packets_dropped();
//               increment_dropped_ipv4_address(iph->saddr);
//               return XDP_DROP;
//             }

//             record_tcp_fingerprint(iph->saddr, tcph->source, tcph, data_end,
//                                    iph->ttl);
//           }

//           if (tcph->fin || tcph->rst) {
//             ip_flag_t one = 1;
//             bpf_map_update_elem(&banned_ips, &key, &one, BPF_ANY);
//             bpf_map_delete_elem(&recently_banned_ips, &key);
//             increment_total_packets_dropped();
//             increment_dropped_ipv4_address(iph->saddr);
//             // bpf_printk("XDP: TCP FIN/RST from incoming recently banned
//             IPv4
//             // %pI4, promoted to permanent ban", &iph->saddr);
//           }
//         }
//       }
//       return XDP_PASS;
//     }

//     // Perform TCP fingerprinting ONLY on SYN packets
//     if (iph->protocol == IPPROTO_TCP) {
//       struct tcphdr *tcph = parse_and_advance(&cursor, data_end,
//       sizeof(*tcph)); if (tcph) {
//         // Only fingerprint SYN packets (not SYN-ACK) to capture MSS/WSCALE
//         if (tcph->syn && !tcph->ack) {
//           increment_tcp_syn_stats();

//           // Generate fingerprint to check if blocked
//           __u8 fingerprint[14] = {0};
//           generate_tcp_fingerprint(tcph, data_end, iph->ttl, fingerprint);

//           // Check if this TCP fingerprint is blocked
//           if (is_tcp_fingerprint_blocked(fingerprint)) {
//             increment_tcp_fingerprint_blocks_ipv4();
//             increment_total_packets_dropped();
//             increment_dropped_ipv4_address(iph->saddr);
//             // bpf_printk("XDP: BLOCKED TCP fingerprint from IPv4 %pI4:%d -
//             // FP:%s",
//             //            &iph->saddr, bpf_ntohs(tcph->source), fingerprint);
//             return XDP_DROP;
//           }

//           // Record fingerprint for monitoring
//           record_tcp_fingerprint(iph->saddr, tcph->source, tcph, data_end,
//                                  iph->ttl);
//         }
//       }
//     }

//     // Check IPv4 port bans
//     if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
//       void *port_cursor = cursor;
//       __be16 src_port = 0;
//       __be16 dst_port = 0;

//       if (iph->protocol == IPPROTO_TCP) {
//         struct tcphdr *tcph_tmp =
//             parse_and_advance(&port_cursor, data_end, sizeof(*tcph_tmp));
//         if (!tcph_tmp)
//           return XDP_PASS;
//         src_port = tcph_tmp->source;
//         dst_port = tcph_tmp->dest;
//       } else {
//         struct udphdr *udph_tmp =
//             parse_and_advance(&port_cursor, data_end, sizeof(*udph_tmp));
//         if (!udph_tmp)
//           return XDP_PASS;
//         src_port = udph_tmp->source;
//         dst_port = udph_tmp->dest;
//       }

//       struct src_port_key_v4 inbound_key = {
//           .addr = iph->saddr,
//           .port = src_port,
//       };

//       if (bpf_map_lookup_elem(&banned_inbound_ipv4_address_ports,
//                               &inbound_key)) {
//         increment_total_packets_dropped();
//         increment_dropped_ipv4_address(iph->saddr);
//         return XDP_DROP;
//       }

//       struct src_port_key_v4 outbound_key = {
//           .addr = iph->daddr,
//           .port = dst_port,
//       };

//       if (bpf_map_lookup_elem(&banned_outbound_ipv4_address_ports,
//                               &outbound_key)) {
//         increment_total_packets_dropped();
//         increment_dropped_ipv4_address(iph->daddr);
//         return XDP_DROP;
//       }
//     }

//     return XDP_PASS;
//   } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
//     struct ipv6hdr *ip6h = parse_and_advance(&cursor, data_end,
//     sizeof(*ip6h)); if (!ip6h)
//       return XDP_PASS;

//     // Always allow DNS traffic (UDP port 53) to pass through
//     if (ip6h->nexthdr == IPPROTO_UDP) {
//       struct udphdr *udph = parse_and_advance(&cursor, data_end,
//       sizeof(*udph)); if (udph &&
//           (udph->dest == bpf_htons(53) || udph->source == bpf_htons(53))) {
//         return XDP_PASS; // Always allow DNS traffic
//       }
//     }

//     // Check banned/recently banned maps by source IPv6
//     struct lpm_key_v6 key6 = {
//         .prefixlen = 128,
//     };
//     // Manual copy for BPF compatibility
//     __u8 *src_addr = (__u8 *)&ip6h->saddr;
// #pragma unroll
//     for (int i = 0; i < 16; i++) {
//       key6.addr[i] = src_addr[i];
//     }

//     if (bpf_map_lookup_elem(&banned_ips_v6, &key6)) {
//       increment_ipv6_banned_stats();
//       increment_total_packets_dropped();
//       increment_dropped_ipv6_address(ip6h->saddr);
//       // bpf_printk("XDP: BLOCKED incoming permanently banned IPv6");
//       return XDP_DROP;
//     }

//     if (bpf_map_lookup_elem(&recently_banned_ips_v6, &key6)) {
//       increment_ipv6_recently_banned_stats();
//       // Block UDP and ICMP from recently banned IPv6 IPs, but allow DNS
//       if (ip6h->nexthdr == IPPROTO_UDP) {
//         struct udphdr *udph =
//             parse_and_advance(&cursor, data_end, sizeof(*udph));
//         if (udph && udph->dest == bpf_htons(53)) {
//           return XDP_PASS; // Allow DNS responses
//         }
//         // Block other UDP traffic
//         ip_flag_t one = 1;
//         bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
//         bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
//         increment_total_packets_dropped();
//         increment_dropped_ipv6_address(ip6h->saddr);
//         // bpf_printk("XDP: BLOCKED incoming UDP from recently banned IPv6,
//         // promoted to permanent ban");
//         return XDP_DROP;
//       }
//       if (ip6h->nexthdr == 58) { // 58 = IPPROTO_ICMPV6
//         ip_flag_t one = 1;
//         bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
//         bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
//         increment_total_packets_dropped();
//         increment_dropped_ipv6_address(ip6h->saddr);
//         // bpf_printk("XDP: BLOCKED incoming ICMPv6 from recently banned
//         IPv6,
//         // promoted to permanent ban");
//         return XDP_DROP;
//       }
//       // For TCP, only promote to banned on FIN/RST
//       if (ip6h->nexthdr == IPPROTO_TCP) {
//         struct tcphdr *tcph =
//             parse_and_advance(&cursor, data_end, sizeof(*tcph));
//         if (tcph) {
//           if (tcph->fin || tcph->rst) {
//             ip_flag_t one = 1;
//             bpf_map_update_elem(&banned_ips_v6, &key6, &one, BPF_ANY);
//             bpf_map_delete_elem(&recently_banned_ips_v6, &key6);
//             increment_total_packets_dropped();
//             increment_dropped_ipv6_address(ip6h->saddr);
//             // bpf_printk("XDP: TCP FIN/RST from incoming recently banned
//             IPv6,
//             // promoted to permanent ban");
//           }
//         }
//       }
//       return XDP_PASS; // Allow if recently banned
//     }

//     // Perform TCP fingerprinting on IPv6 TCP packets
//     if (ip6h->nexthdr == IPPROTO_TCP) {
//       struct tcphdr *tcph = parse_and_advance(&cursor, data_end,
//       sizeof(*tcph)); if (tcph) {
//         // Perform TCP fingerprinting ONLY on SYN packets (not SYN-ACK)
//         // This ensures we capture the initial handshake with MSS/WSCALE
//         if (tcph->syn && !tcph->ack) {
//           // Skip IPv6 localhost traffic to reduce noise
//           // Check for ::1 (IPv6 localhost) - manual comparison
//           __u8 *src_addr = (__u8 *)&ip6h->saddr;
//           bool is_localhost = true;

// // Check first 15 bytes are zero
// #pragma unroll
//           for (int i = 0; i < 15; i++) {
//             if (src_addr[i] != 0) {
//               is_localhost = false;
//               break;
//             }
//           }
//           // Check last byte is 1
//           if (is_localhost && src_addr[15] == 1) {
//             return XDP_PASS;
//           }

//           if (ipv6_syn_ratelimit(src_addr) == XDP_DROP) {
//             return XDP_DROP;
//           }

//           // Extract TTL from IPv6 hop limit
//           __u16 ttl = ip6h->hop_limit;

//           // Generate fingerprint to check if blocked
//           __u8 fingerprint[14] = {0};
//           generate_tcp_fingerprint(tcph, data_end, ttl, fingerprint);

//           // Check if this TCP fingerprint is blocked
//           if (is_tcp_fingerprint_blocked_v6(fingerprint)) {
//             increment_tcp_fingerprint_blocks_ipv6();
//             increment_total_packets_dropped();
//             increment_dropped_ipv6_address(ip6h->saddr);
//             // bpf_printk("XDP: BLOCKED TCP fingerprint from IPv6 %pI6:%d -
//             // FP:%s",
//             //            &ip6h->saddr, bpf_ntohs(tcph->source),
//             fingerprint); return XDP_DROP;
//           }

//           // Create IPv6 fingerprint key with full 128-bit address
//           struct tcp_fingerprint_key_v6 key = {0};
//           struct tcp_fingerprint_data data = {0};
//           __u64 timestamp = bpf_ktime_get_ns();

// // Copy full IPv6 address (16 bytes) - manual copy for BPF
// #pragma unroll
//           for (int i = 0; i < 16; i++) {
//             key.src_ip[i] = src_addr[i];
//           }
//           key.src_port = tcph->source;

// // Copy fingerprint to key
// #pragma unroll
//           for (int i = 0; i < 14; i++) {
//             key.fingerprint[i] = fingerprint[i];
//           }

//           // Check if fingerprint already exists in IPv6 map
//           struct tcp_fingerprint_data *existing =
//               bpf_map_lookup_elem(&tcp_fingerprints_v6, &key);
//           if (existing) {
//             // Update existing entry - must copy to local variable first
//             data.first_seen = existing->first_seen;
//             data.last_seen = timestamp;
//             data.packet_count = existing->packet_count + 1;
//             data.ttl = existing->ttl;
//             data.mss = existing->mss;
//             data.window_size = existing->window_size;
//             data.window_scale = existing->window_scale;
//             data.options_len = existing->options_len;

// // Copy options array
// #pragma unroll
//             for (int i = 0; i < TCP_FP_MAX_OPTION_LEN; i++) {
//               data.options[i] = existing->options[i];
//             }

//             bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
//           } else {
//             // Create new entry
//             data.first_seen = timestamp;
//             data.last_seen = timestamp;
//             data.packet_count = 1;
//             data.ttl = ttl;
//             data.window_size = bpf_ntohs(tcph->window);

//             // Extract MSS and window scale from options
//             parse_tcp_mss_wscale(tcph, data_end, &data.mss,
//             &data.window_scale);

//             bpf_map_update_elem(&tcp_fingerprints_v6, &key, &data, BPF_ANY);
//             increment_unique_fingerprints();

//             // Log new IPv6 TCP fingerprint
//             // bpf_printk("TCP_FP: New IPv6 fingerprint from %pI6:%d - TTL:%d
//             // MSS:%d WS:%d Window:%d",
//             //           &ip6h->saddr, bpf_ntohs(tcph->source), ttl,
//             data.mss,
//             //           data.window_scale, data.window_size);
//           }
//         }
//       }
//     }

//     // Check IPv6 port bans
//     if (ip6h->nexthdr == IPPROTO_TCP || ip6h->nexthdr == IPPROTO_UDP) {
//       void *port_cursor = cursor;
//       __be16 src_port = 0;
//       __be16 dst_port = 0;

//       if (ip6h->nexthdr == IPPROTO_TCP) {
//         struct tcphdr *tcph_tmp =
//             parse_and_advance(&port_cursor, data_end, sizeof(*tcph_tmp));
//         if (!tcph_tmp)
//           return XDP_PASS;
//         src_port = tcph_tmp->source;
//         dst_port = tcph_tmp->dest;
//       } else {
//         struct udphdr *udph_tmp =
//             parse_and_advance(&port_cursor, data_end, sizeof(*udph_tmp));
//         if (!udph_tmp)
//           return XDP_PASS;
//         src_port = udph_tmp->source;
//         dst_port = udph_tmp->dest;
//       }

//       struct src_port_key_v6 inbound_key6 = {0};
// #pragma unroll
//       for (int i = 0; i < 16; i++) {
//         inbound_key6.addr[i] = ((__u8 *)&ip6h->saddr)[i];
//       }
//       inbound_key6.port = src_port;

//       if (bpf_map_lookup_elem(&banned_inbound_ipv6_address_ports,
//                               &inbound_key6)) {
//         increment_total_packets_dropped();
//         increment_dropped_ipv6_address(ip6h->saddr);
//         return XDP_DROP;
//       }

//       struct src_port_key_v6 outbound_key6 = {0};
// #pragma unroll
//       for (int i = 0; i < 16; i++) {
//         outbound_key6.addr[i] = ((__u8 *)&ip6h->daddr)[i];
//       }
//       outbound_key6.port = dst_port;

//       if (bpf_map_lookup_elem(&banned_outbound_ipv6_address_ports,
//                               &outbound_key6)) {
//         increment_total_packets_dropped();
//         increment_dropped_ipv6_address(ip6h->daddr);
//         return XDP_DROP;
//       }
//     }

//     return XDP_PASS;
//   }

//   return XDP_PASS;
   // return XDP_ABORTED;
 }

char _license[] SEC("license") = "GPL";
