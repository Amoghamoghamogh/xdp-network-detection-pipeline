# SPDX-License-Identifier: GPL-2.0
#
# Makefile — build the XDP/eBPF pipeline
#
# Requirements:
#   clang >= 12, llvm, libbpf-dev, linux-headers, bpftool
#
# Targets:
#   all      — compile BPF object + generate libbpf skeleton
#   clean    — remove build artefacts
#   fmt      — clang-format all kernel sources
#   check    — run bpftool prog load dry-run (verifier check)

# ── Toolchain ──────────────────────────────────────────────────────────────
CC        := clang
BPFTOOL   := bpftool
FMT       := clang-format

# ── Paths ──────────────────────────────────────────────────────────────────
KERNEL_SRC  := kernel/xdp_pipeline.bpf.c
BPF_OBJ     := build/xdp_pipeline.bpf.o
SKEL_HDR    := userspace/xdp_pipeline.skel.h

VMLINUX_HDR := kernel/vmlinux.h

# ── Compiler flags ─────────────────────────────────────────────────────────
BPF_CFLAGS := \
  -g -O2 -Wall \
  -target bpf \
  -D__TARGET_ARCH_x86 \
  -I kernel \
  -I /usr/include/bpf \
  $(shell pkg-config --cflags libbpf 2>/dev/null)

# ── Targets ────────────────────────────────────────────────────────────────
.PHONY: all clean fmt check vmlinux

all: $(BPF_OBJ) $(SKEL_HDR)

$(BPF_OBJ): $(KERNEL_SRC) kernel/maps.h kernel/common.h \
             kernel/modules/firewall.h \
             kernel/modules/tcp_fingerprint.h \
             kernel/modules/latency.h
	@mkdir -p build
	$(CC) $(BPF_CFLAGS) -c $< -o $@
	@echo "[OK] BPF object: $@"

$(SKEL_HDR): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[OK] Skeleton header: $@"

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_HDR)
	@echo "[OK] vmlinux.h generated"

fmt:
	$(FMT) -i kernel/*.h kernel/*.c kernel/modules/*.h

check: $(BPF_OBJ)
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/xdp_pipeline_check 2>&1 || true
	@rm -f /sys/fs/bpf/xdp_pipeline_check

clean:
	rm -rf build $(SKEL_HDR)
