#pragma once

#include "common.h"

#include "../xdp_maps.h"
#include "vmlinux.h"

struct lpm_key {
  __u32 prefixlen;
  __be32 addr;
};

struct lpm_key_v6 {
  __u32 prefixlen;
  __u8 addr[16];
};

struct src_port_key_v4 {
  __be32 addr;
  __be16 port;
};

struct src_port_key_v6 {
  __u8 addr[16];
  __be16 port;
};

/*
 * Helper functions for incrementing statistics counters
 */
static __always_inline void increment_ipv4_banned_stats(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&ipv4_banned_stats, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_ipv4_recently_banned_stats(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&ipv4_recently_banned_stats, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_ipv6_banned_stats(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&ipv6_banned_stats, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_ipv6_recently_banned_stats(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&ipv6_recently_banned_stats, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_total_packets_processed(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&total_packets_processed, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_total_packets_dropped(void) {
  __u32 key = 0;
  __u64 *value = bpf_map_lookup_elem(&total_packets_dropped, &key);
  if (value) {
    __sync_fetch_and_add(value, 1);
  }
}

static __always_inline void increment_dropped_ipv4_address(__be32 ip_addr) {
  __u64 *value = bpf_map_lookup_elem(&dropped_ipv4_addresses, &ip_addr);
  if (value) {
    __sync_fetch_and_add(value, 1);
  } else {
    // First time dropping this IP, initialize counter
    __u64 initial_count = 1;
    bpf_map_update_elem(&dropped_ipv4_addresses, &ip_addr, &initial_count,
                        BPF_ANY);
  }
}

static __always_inline void
increment_dropped_ipv6_address(struct in6_addr ip_addr) {
  __u8 *addr_bytes = (__u8 *)&ip_addr;
  __u64 *value = bpf_map_lookup_elem(&dropped_ipv6_addresses, addr_bytes);
  if (value) {
    __sync_fetch_and_add(value, 1);
  } else {
    // First time dropping this IP, initialize counter
    __u64 initial_count = 1;
    bpf_map_update_elem(&dropped_ipv6_addresses, addr_bytes, &initial_count,
                        BPF_ANY);
  }
}

static __noinline int xdp_portban(struct iphdr *iph, struct tcphdr *tcph,
                                  struct udphdr *udph) {

  if (!iph) {
    return XDP_PASS;
  }

  __be16 src_port = 0;
  __be16 dst_port = 0;

  if (tcph) {
    src_port = tcph->source;
    dst_port = tcph->dest;
  } else if (udph) {
    src_port = udph->source;
    dst_port = udph->dest;
  } else {
    return XDP_PASS;
  }

  struct src_port_key_v4 inbound_key = {
      .addr = iph->saddr,
      .port = src_port,
  };

  if (bpf_map_lookup_elem(&banned_inbound_ipv4_address_ports, &inbound_key)) {
    increment_total_packets_dropped();
    increment_dropped_ipv4_address(iph->saddr);
    return XDP_DROP;
  }

  struct src_port_key_v4 outbound_key = {
      .addr = iph->daddr,
      .port = dst_port,
  };

  if (bpf_map_lookup_elem(&banned_outbound_ipv4_address_ports, &outbound_key)) {
    increment_total_packets_dropped();
    increment_dropped_ipv4_address(iph->daddr);
    return XDP_DROP;
  }

  return XDP_PASS;
}

static __noinline int xdp_firewall(struct iphdr *iph, struct ipv6hdr *ip6h) {

  if (iph) {
    struct lpm_key key = {
        .prefixlen = 32,
        .addr = iph->saddr,
    };

    if (bpf_map_lookup_elem(&banned_ips, &key)) {
      increment_ipv4_banned_stats();
      increment_total_packets_dropped();
      increment_dropped_ipv4_address(iph->saddr);
      // bpf_printk("XDP: BLOCKED incoming permanently banned IPv4 %pI4",
      // &iph->saddr);
      return XDP_DROP;
    }
  } else if (ip6h) {
    struct lpm_key_v6 key6 = {.prefixlen = 128};

    __builtin_memcpy(&key6.addr, &ip6h->saddr, sizeof(ip6h->saddr));

    if (bpf_map_lookup_elem(&banned_ips_v6, &key6)) {
      increment_ipv6_banned_stats();
      increment_total_packets_dropped();
      increment_dropped_ipv6_address(ip6h->saddr);
      // bpf_printk("XDP: BLOCKED incoming permanently banned IPv6");
      return XDP_DROP;
    }
  }

  return XDP_PASS;
}
