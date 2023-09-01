# Roadmap

This project involves evaluating Ghidra's ability to track evolutions in the RISCV-64 instruction set architecture.
If we wanted to resolve a possible race condition in a many-core RISCV-64 network appliance, would Ghidra help?
What would we need to add to Ghidra over the next 3 years in order to be useful in identifying the wrong atomic,
cache coherency, or memory barrier instuction sequence?

The first step is to verify that Ghidra works well with current-generation RISCV-64 network code.  Next we need to
predict the evolution paths for components of a RISCV-64 network appliance toolchain.  Then we can start working up
possible add-ons to Ghidra to keep pace.

## Hardware

https://www.sifive.com/boards/hifive-pro-p550

https://liliputing.com/sifive-hifive-pro-p550-dev-board-coming-this-summer-with-intel-horse-creek-risc-v-chip/

https://www.cnx-software.com/2022/11/02/sifive-p670-and-p470-risc-v-processors-add-risc-v-vector-extensions/

https://www.cnx-software.com/2023/08/30/sifive-unveils-p870-high-performance-core-discusses-future-of-risc-v

https://github.com/riscv/riscv-profiles/blob/main/rva23-profile.adoc

https://www.scmp.com/tech/tech-trends/article/3232686/chinas-top-chip-designers-form-risc-v-patent-alliance-promote-semiconductor-self-sufficiency

We might expect to see high performance network appliances in 2026 using chip architectures like the Sifive 670 or 870,
or from one of the alternative Chinese vendors.  Chips with vector extensions are due soon, with crypto extensions coming shortly after.
A network appliance development board might have two P670 class sockets and four to eight 10 GbE network interfaces.

To manage scope, we won't be worrying about instructions supporting AI or complex virtualization.  Custom instructions that might be used
in network appliances are definitely in scope, while custom instructions for nested virtualization are not.  Possibly in scope are new instructions
that help manage or synchronize multi-socket cache memory.

## Software

Assume a Linux 6+ kernel and network stack serving two P670 class sockets and four to eight 10 GbE network interfaces. Network processing
provides both the traditional Linux kernel IP stack and XDR/BPF diversion from NIC driver into user space.

Problem areas to expect race conditions range from using the wrong memory barrier instruction (`fence`) to complex interactions between device memory, cache control, and kernel page table management.  

### race condition stress test

To stress race condition
management we assume link bonding with failover.  Inbound traffic is distributed over two physical interfaces, each served by different
RISCV-64 processor sockets.  Output traffic is similarly distributed.  Inbound packets from the two inbound physical links need to
be handled as if from a single source.  Output packets need to be distributed across the two outbound physical links with minimal need for
packet reordering at the remote destination.  If one of the outbound physical links fails, then *all* outbound packets need to be delivered
through the surviving outbound link.

