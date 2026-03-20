/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

/*
 * userspace/loader.h — libbpf-based XDP program loader (stub).
 *
 * TODO: implement with libbpf skeleton generated from xdp_pipeline.bpf.c.
 *
 * Typical flow:
 *   1. xdp_pipeline_bpf__open()   — open the BPF object
 *   2. xdp_pipeline_bpf__load()   — load and verify programs
 *   3. bpf_xdp_attach()           — attach to target interface
 *   4. poll BPF maps for telemetry
 *   5. bpf_xdp_detach() on exit
 *
 * Build skeleton:
 *   bpftool gen skeleton kernel/xdp_pipeline.bpf.o > userspace/xdp_pipeline.skel.h
 */

#include <bpf/libbpf.h>
#include <net/if.h>

/**
 * xdp_attach - load and attach the XDP pipeline to @ifname.
 * Returns 0 on success, negative errno on failure.
 */
static inline int xdp_attach(const char *ifname) {
  /* TODO: implement using generated skeleton */
  (void)ifname;
  return -ENOSYS;
}

/**
 * xdp_detach - detach the XDP program from @ifname.
 */
static inline int xdp_detach(const char *ifname) {
  /* TODO: implement using generated skeleton */
  (void)ifname;
  return -ENOSYS;
}
