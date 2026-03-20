#!/usr/bin/env bash
# detach.sh — detach the XDP pipeline from a network interface.
#
# Usage: sudo ./scripts/detach.sh <interface>

set -euo pipefail

IFACE="${1:?Usage: $0 <interface>}"
PIN_PATH="/sys/fs/bpf/xdp_pipeline"

echo "Detaching XDP program from $IFACE ..."
ip link set dev "$IFACE" xdp off

echo "Removing pinned BPF objects ..."
rm -rf "$PIN_PATH"

echo "Done. XDP pipeline detached from $IFACE."
