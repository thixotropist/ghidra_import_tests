# Sidebar studies

## will vector instructions be useful in network appliances?

Network kernel code has lots of conditional branches and very few loops.  This suggests RISCV vector instructions won't be
found in network appliances anytime soon, other than `memmove` or similar simple contexts.  Gather-scatter, bit manipulation, and
crypto instruction extensions are likely to be useful in networking much sooner.  Ghidra will have a much easier time generating
pcode for those instructions than the 25K+ RISCV vector instrinsic C functions covering all combinations of vector instructions and
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
An adaptive midpoint network appliance might adjust the packet classification code in realtime, based on the mix of MPLS, VLAN, IPv4, IPv6, and VPN traffic most often seen on
any given network interface.  ISA extensions supporting gather, hash, vector comparison, and find-first operations are good candidates here.

## role of mixed 32 and 64 bit cores

Consider a midpoint network appliance (router or firewall) sitting near the Provider-Customer demarcation.  What might be an appealing RISCV processor look like?
This kind of appliance likely handles a mix of link layer protocols with an optimization for low energy dissipation and low latency per packet.  A fast and simple
serializer/deserializer feeding a RISCV classifier and forwarding engine makes sense here.  You don't want to do network or application layer processing unless the appliance
has a firewall role.

Link layer processing means a packet mix of stacked MPLS and VLAN tags with IPv4 and IPv6 network layers underneath.  Packet header processing won't need 32 bit addressing,
but might benefit from the high memory bandwidth of a 64 bit core.  Fast header hashing combined with fast hashmap session lookups (for MPLS, VLAN, and selected IP) or
fash trie session lookups (for IPv4 and IPv6).  Network stacks can have a lot of branches, creating pipeline stalls, so hyperthreading may make sense.

Denial of Service and overload protections make fast analytics necessary at the session level.  That's where a 64 bit core with vector and other extensions can be useful.

This all suggests we might see more hybrid RISCV designs, with a mix of many lean 32 bit cores supported by one or two 64 bit cores.  The 32 bit cores handle fast link layer processing
and the 64 bit cores handle background analytics and control.

In the extreme case, the 64 bit analytics engine rewrites link layer code for the 32 bit cores continuously, optimizing code paths depending on what the link layer classifiers
determine the most common packet types to be for each physical port.  Cache management and branch prediction hints might drive new instruction additions.

Code rewriting could start as simple updates to RISCV hint branch instructions and possibly prefetch instructions, so it isn't necessarily as radical as it sounds.

