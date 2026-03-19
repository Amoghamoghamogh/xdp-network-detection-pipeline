#pragma once

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NF_DROP 0
#define NF_ACCEPT 1
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define NEXTHDR_FRAGMENT 44

#define CITADEL_IP_MAP_MAX 65536

typedef __u8 ip_flag_t;

typedef __u8 ipv6_addr[16];
