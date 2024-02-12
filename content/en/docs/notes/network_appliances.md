---
title: Network Appliances
linkTitle: Network Appliances
weight: 20
---

{{% pageinfo %}}
What will RISCV-64 cores offer networking? 
{{% /pageinfo %}}

## will vector instructions be useful in network appliances?

Network kernel code has lots of conditional branches and very few loops.  This suggests RISCV vector instructions won't be
found in network appliances anytime soon, other than `memmove` or similar simple contexts.  Gather-scatter, bit manipulation, and
crypto instruction extensions are likely to be useful in networking much sooner.  Ghidra will have a much easier time generating
pcode for those instructions than the 25K+ RISCV vector intrinsic C functions covering all combinations of vector instructions and
vector processing modes.

What should Ghidra do when faced with a counter-example, say a network appliance that aggressively moves vector analytics into network processing?
Such an appliance - perhaps a smart edge router or a zero-trust gateway device - might combine the following:

* 64 RISCV cores with no floating point or vector capability, optimized for traditional network ingress processing.  These cores are
  designed to cope with the many branches of network packet processing, possibly including better branch prediction and hyperthreading.
* 2 or more RISCV cores with full floating point and vector capability, optimized for performing analytics on the inbound packet stream.
  These analytics can range from simple statistics generation to heuristic sessionization to self-modifying code generation.
  The self-modifying code may be either eBPF code or native RISCV instructions, depending on how aggressive the designers may be.

In the extreme case, this might be a generative AI subsystem trained on inbound packets and emitting either optimized packet handling code or
threat-detection indicators.  How would a Ghidra analyst look for malware in such a system?

### midpoint versus endpoint network appliances

We need to be clearer about what kind of network code we might find in different contexts:

* midpoint equipment like network-edge routers and switches, optimized for maximum throughput
* endpoint equipment like host computers, web servers, and database servers where applications take up the bulk of the CPU cycles

For each of these contexts we have at least two topology variants:

* Inline network code through which packets must transit, generally optimized for low latency and high throughput
* Tapped network code (e.g., wireshark or port-mirrored accesses) observing copies of packets for session and endpoint analytics.
  Latency is not an issue here.

Midpoint network appliances may need to track session state.  A simple network switch is close to stateless.  A real-world network switch
has a lot of session state to manage if it supports:

* denial of service overload detection or other flow control
* link bonding or equal-weight multipath routing

The key point here is that midpoint network appliances may benefit from instruction set extensions that enable faster packet classification, hashing, and cached session lookup.
An adaptive midpoint network appliance might adjust the packet classification code in real-time, based on the mix of MPLS, VLAN, IPv4, IPv6, and VPN traffic most often seen on
any given network interface.  ISA extensions supporting gather, hash, vector comparison, and find-first operations are good candidates here.
