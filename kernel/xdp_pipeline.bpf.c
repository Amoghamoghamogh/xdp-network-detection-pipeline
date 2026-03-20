// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_pipeline.bpf.c — XDP packet processing pipeline.
 *
 * Attach point: XDP ingress hook on the target NIC.
 *
 * Pipeline stages (in order):
 *   1. Packet counter increment
 *   2. Ethernet header parse
 *   3. IP header parse (IPv4 / IPv6)
 *   4. Transport header parse (TCP / UDP)
 *   5. IP firewall  — LPM-trie ban check
 *   6. Port filter  — (IP, port) ban check
 *   7. TCP SYN fingerprinting — JA4T-style, with block-list enforcement
 *   8. TCP handshake latency  — JA4L-inspired RTT measurement
 *
 * Note: JA4TS SYN-ACK capture is handled by a separate TC BPF program.
 */

#include "common.h"
#include "maps.h"
#include "modules/firewall.h"
#include "modules/tcp_fingerprint.h"
#include "modules/latency.h"
#include "vmlinux.h"

SEC("xdp")
int xdp_pipeline(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *cursor   = (void *)(long)ctx->data;

  /* Stage 1: count every packet that enters the pipeline */
  stats_inc_pkts_total();

  /* Stage 2: Ethernet */
  struct ethhdr *eth = parse_and_advance(&cursor, data_end, sizeof(*eth));
  if (!eth)
    return XDP_PASS;

  /* Stage 3: IP */
  struct iphdr   *iph  = NULL;
  struct ipv6hdr *ip6h = NULL;

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    iph = parse_and_advance(&cursor, data_end, sizeof(*iph));
    if (!iph)
      return XDP_PASS;
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    ip6h = parse_and_advance(&cursor, data_end, sizeof(*ip6h));
    if (!ip6h)
      return XDP_PASS;
  } else {
    return XDP_PASS; /* non-IP traffic — pass through */
  }

  /* Stage 4: Transport */
  struct tcphdr *tcph = NULL;
  struct udphdr *udph = NULL;

  bool is_tcp = (iph  && iph->protocol  == IPPROTO_TCP) ||
                (ip6h && ip6h->nexthdr  == IPPROTO_TCP);
  bool is_udp = (iph  && iph->protocol  == IPPROTO_UDP) ||
                (ip6h && ip6h->nexthdr  == IPPROTO_UDP);

  if (is_tcp) {
    tcph = parse_and_advance(&cursor, data_end, sizeof(*tcph));
    if (!tcph)
      return XDP_PASS;
  } else if (is_udp) {
    udph = parse_and_advance(&cursor, data_end, sizeof(*udph));
    if (!udph)
      return XDP_PASS;
  }

  /* Stage 5: IP firewall */
  if (xdp_ip_filter(iph, ip6h) == XDP_DROP)
    return XDP_DROP;

  /* Stage 6: Port filter */
  if (xdp_port_filter(iph, tcph, udph) == XDP_DROP)
    return XDP_DROP;

  /* Stage 7: TCP SYN fingerprinting */
  if (xdp_tcp_fingerprint(ctx, iph, ip6h, tcph) == XDP_DROP)
    return XDP_DROP;

  /* Stage 8: TCP handshake latency tracking */
  if (tcph) {
    if (iph)
      track_latency_v4(iph, tcph, data_end);
    else if (ip6h)
      track_latency_v6(ip6h, tcph, data_end);
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
