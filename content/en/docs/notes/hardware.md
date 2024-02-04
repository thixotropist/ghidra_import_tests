---
title: Hardware Availability
linkTitle: Hardware Availability
weight: 10
---

{{% pageinfo %}}
When will RISCV-64 cores be deployed into systems needing reverse-engineering? 
{{% /pageinfo %}}


## General purpose systems

https://www.sifive.com/boards/hifive-pro-p550

https://liliputing.com/sifive-hifive-pro-p550-dev-board-coming-this-summer-with-intel-horse-creek-risc-v-chip/

https://www.cnx-software.com/2022/11/02/sifive-p670-and-p470-risc-v-processors-add-risc-v-vector-extensions/

https://www.cnx-software.com/2023/08/30/sifive-unveils-p870-high-performance-core-discusses-future-of-risc-v

https://github.com/riscv/riscv-profiles/blob/main/rva23-profile.adoc

https://www.scmp.com/tech/tech-trends/article/3232686/chinas-top-chip-designers-form-risc-v-patent-alliance-promote-semiconductor-self-sufficiency

We might expect to see high performance network appliances in 2026 using chip architectures like the SiFive 670 or 870,
or from one of the alternative Chinese vendors.  Chips with vector extensions are due soon, with crypto extensions coming shortly after.
A network appliance development board might have two P670 class sockets and four to eight 10 GbE network interfaces.

To manage scope, we won't be worrying about instructions supporting AI or complex virtualization.  Custom instructions that might be used
in network appliances are definitely in scope, while custom instructions for nested virtualization are not.  Possibly in scope are new instructions
that help manage or synchronize multi-socket cache memory.

Let's set a provocative long term goal: How will Ghidra analyze a future network appliance that combines Machine Learning with self-modifying code
to accelerate network routing and forwarding?  Such a device might generate fast-path code sequences to sessionize incoming packets and deliver them with
minimal cache flushes or branches taken.

## Portable appliances

This might include cell phones or voice-recognition apps.  Things that today might use an Arm core set but be implemented with RISC-V cores in the future.

## role of mixed 32 and 64 bit cores

Consider a midpoint network appliance (router or firewall) sitting near the Provider-Customer demarcation.  What might be an appealing RISCV processor look like?
This kind of appliance likely handles a mix of link layer protocols with an optimization for low energy dissipation and low latency per packet.  A fast and simple
serializer/deserializer feeding a RISCV classifier and forwarding engine makes sense here.  You don't want to do network or application layer processing unless the appliance
has a firewall role.

Link layer processing means a packet mix of stacked MPLS and VLAN tags with IPv4 and IPv6 network layers underneath.  Packet header processing won't need 32 bit addressing,
but might benefit from the high memory bandwidth of a 64 bit core.  Fast header hashing combined with fast hashmap session lookups (for MPLS, VLAN, and selected IP) or
fast trie session lookups (for IPv4 and IPv6).  Network stacks can have a lot of branches, creating pipeline stalls, so hyperthreading may make sense.

Denial of Service and overload protections make fast analytics necessary at the session level.  That's where a 64 bit core with vector and other extensions can be useful.

This all suggests we might see more hybrid RISCV designs, with a mix of many lean 32 bit cores supported by one or two 64 bit cores.  The 32 bit cores handle fast link layer processing
and the 64 bit cores handle background analytics and control.

In the extreme case, the 64 bit analytics engine rewrites link layer code for the 32 bit cores continuously, optimizing code paths depending on what the link layer classifiers
determine the most common packet types to be for each physical port.  Cache management and branch prediction hints might drive new instruction additions.

Code rewriting could start as simple updates to RISCV hint branch instructions and possibly prefetch instructions, so it isn't necessarily as radical as it sounds.

