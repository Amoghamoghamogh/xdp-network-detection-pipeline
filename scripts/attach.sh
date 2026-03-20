#!/usr/bin/env bash
# attach.sh — attach the XDP pipeline to a network interface.
#
# Usage: sudo ./scripts/attach.sh <interface> [native|skb]
#   interface  — e.g. eth0, ens3
#   mode       — native (default, requires driver support) or skb (generic)
#
# Requires: ip (iproute2), bpftool, build/xdp_pipeline.bpf.o

set -euo pipefail

IFACE="${1:?Usage: $0 <interface> [native|skb]}"
MODE="${2:-native}"
OBJ="build/xdp_pipeline.bpf.o"
PIN_PATH="/sys/fs/bpf/xdp_pipeline"

if [[ ! -f "$OBJ" ]]; then
  echo "ERROR: BPF object not found at $OBJ — run 'make' first." >&2
  exit 1
fi

if [[ "$MODE" == "native" ]]; then
  XDP_FLAG="xdpdrv"
elif [[ "$MODE" == "skb" ]]; then
  XDP_FLAG="xdpgeneric"
else
  echo "ERROR: unknown mode '$MODE'. Use 'native' or 'skb'." >&2
  exit 1
fi

echo "Pinning BPF maps to $PIN_PATH ..."
mkdir -p "$PIN_PATH"
bpftool prog load "$OBJ" "$PIN_PATH/prog" \
  pinmaps "$PIN_PATH/maps"

echo "Attaching XDP program to $IFACE ($MODE mode) ..."
ip link set dev "$IFACE" "$XDP_FLAG" pinned "$PIN_PATH/prog"

echo "Done. XDP pipeline attached to $IFACE."
echo "  Maps pinned at: $PIN_PATH/maps"
echo "  Detach with:    sudo ./scripts/detach.sh $IFACE"
