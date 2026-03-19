# XDP-Based Network Detection Pipeline

## Overview

This project implements a high-performance network packet processing pipeline using eBPF/XDP for early-stage threat detection and traffic filtering.

The system performs packet inspection at the XDP hook (pre-SKB allocation), enabling low-latency filtering before packets enter the kernel networking stack.

---

## Architecture

```
Incoming Traffic
        ↓
[XDP Layer]
- Firewall (IP filtering)
- Port-based filtering
- TCP fingerprinting
- Latency tracking
        ↓
Decision Engine
├── DROP → malicious traffic
├── PASS → kernel (Suricata / normal processing)
└── REDIRECT → AF_XDP (custom analysis)
```

---

## Key Features

* High-speed packet parsing at XDP layer
* IPv4 and IPv6 support
* TCP SYN fingerprinting (JA4T-style)
* Port-based filtering and IP banning
* Connection latency tracking (JA4L concept)
* Modular pipeline design

---

## Detection Strategy

The system classifies packets into three categories:

1. **Known Malicious**

   * Blocked IPs / ports
   * Known bad TCP fingerprints
     → Dropped immediately (XDP_DROP)

2. **Suspicious Traffic**

   * Fragmented packets
   * Unusual TCP SYN behavior
   * Anomalous patterns
     → Redirected to user space (AF_XDP)

3. **Normal Traffic**
   → Passed to kernel for further inspection (e.g., Suricata)

---

## AF_XDP Role (Deep Analysis Layer)

While XDP performs fast, early-stage filtering, AF_XDP handles deeper and stateful packet analysis that is not feasible within eBPF constraints.

### 1. Fragment Reassembly

* Collect fragmented packets
* Reassemble full payload
* Detect fragmentation-based evasion

Example:

```
Fragment 1 → harmless  
Fragment 2 → harmless  
Combined → malicious payload  
```

→ XDP cannot reconstruct full payload
→ AF_XDP detects the attack

---

### 2. Advanced TCP Fingerprint Validation

* Correlate fingerprints across multiple packets
* Detect:

  * Inconsistent fingerprints
  * Spoofed TCP stacks
  * Scanning behavior

---

### 3. Behavioral Analysis

* Track traffic patterns per source
* Detect:

  * Port scans (same IP → multiple ports)
  * SYN floods (beyond simple rate limits)
  * Timing anomalies

---

### 4. Payload Inspection (Light DPI)

* Inspect packet payloads in user space
* Detect:

  * Suspicious strings
  * Malformed packets
  * Protocol violations

---

### 5. Feedback Loop to XDP

AF_XDP updates BPF maps based on analysis:

```c
bpf_map_update_elem(&banned_ips, ...);
bpf_map_update_elem(&blocked_tcp_fingerprints, ...);
```

→ Future packets are dropped early at XDP
→ Improves performance and reduces attack surface

---

## libpcap-Based Traffic Analysis

To complement XDP and AF_XDP processing, traffic analysis is performed using libpcap-based tools.

### Capabilities

* Capture live network traffic and PCAP files
* Analyze packet headers and flows
* Detect:

  * Port scanning behavior
  * SYN flood patterns
  * Suspicious connection attempts

### Example Workflow

```
Scapy → Generate traffic  
↓  
libpcap → Capture & analyze packets  
↓  
Extract patterns / anomalies  
```

This provides an additional validation layer and supports offline forensic analysis.

---

## Threat Intelligence Integration

### MITRE ATT&CK Mapping

Observed behaviors are mapped to MITRE ATT&CK techniques for structured threat analysis:

* **T1046 – Network Service Scanning**
  → Multiple SYN packets across ports

* **T1498 – Network Denial of Service**
  → High-rate SYN flood patterns

* **T1562 – Impair Defenses (Evasion)**
  → Fragmentation-based evasion techniques

---

### Indicators of Compromise (IoCs)

The system extracts and tracks IoCs from analyzed traffic:

* Malicious source IP addresses
* Suspicious TCP fingerprints
* Abnormal port usage patterns
* Repeated anomalous connection attempts

These IoCs are stored in BPF maps and used for:

* Real-time blocking at XDP
* Future traffic correlation
* Threat intelligence enrichment

---

## Why XDP?

* Runs before SKB allocation → reduces kernel overhead
* Enables early packet filtering
* Improves performance under high traffic load

---

## Validation

Traffic simulation and validation were performed using Scapy, Wireshark, and libpcap:

* Fragmented packet generation
* Packet capture and analysis
* TCP behavior inspection
* Detection of anomalous patterns


---

## Limitations

* eBPF programs are constrained (no heavy loops, limited memory)
* Deep packet inspection requires user-space handling (AF_XDP / Suricata)
* Limited application-layer visibility at XDP level

---

## Future Improvements

* Full AF_XDP userspace implementation
* Dynamic rule updates via control plane
* Integration with external threat intelligence feeds
* Advanced anomaly detection (ML-based)
