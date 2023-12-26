SHELL := bash
GHIDRA_VERSION := 11.1_DEV
Fedora_riscv_site := http://fedora.riscv.rocks/kojifiles/work/tasks/6900/1466900
Fedora_riscv_image := Fedora-Developer-39-20230927.n.0-sda.raw
Fedora_kernel := vmlinuz-6.5.4-300.0.riscv64.fc39.riscv64
Fedora_kernel_offset := 40056
Fedora_kernel_decompressed := vmlinux-6.5.4-300.0.riscv64.fc39.riscv64
Fedora_sysmap := System.map-6.5.4-300.0.riscv64.fc39.riscv64

Toolchain_exemplar_dir := riscv64/exemplars
Toolchain_exemplar_logdir := riscv64/exemplars/logs

# most extensions are either ratified or frozen, guaranteed to not overlap in opcode assignments
Toolchain_exemplar_common_names := b-ext-64 b-ext h-ext-64 rvv_index.pic rvv_matmul.pic rvv_memcpy.pic \
	rvv_reduce.pic rvv_strncpy.pic vector zbkb-64 zbkc zbkx \
	zca zcb zknd-64 zkne-64 zknh-64 zksed zksh zvbb zvbc zvkng zvksg

# vendor-specific extensions from THead Alibaba - these need an explicit vendor-specific processor variant
Toolchain_exemplar_thead_names := ba bb bs cmo condmov \
	fmemidx mac memidx mempair sync

Toolchain_exemplar_common_objects := $(foreach name,$(Toolchain_exemplar_common_names),$(Toolchain_exemplar_dir)/$(name).o)
Toolchain_exemplar_common_logs := $(foreach name,$(Toolchain_exemplar_common_names),$(Toolchain_exemplar_logdir)/$(name).log)
Toolchain_exemplar_thead_objects := $(foreach name,$(Toolchain_exemplar_common_names),$(Toolchain_exemplar_dir)/x-thead-$(name).o)
Toolchain_exemplar_thead_logs := $(foreach name,$(Toolchain_exemplar_thead_names),$(Toolchain_exemplar_logdir)/x-thead-$(name).log)

Analyzer := /opt/ghidra_$(GHIDRA_VERSION)/support/analyzeHeadless

CurrentDir := $(strip $(shell pwd))
TestResultsDir :=$(CurrentDir)/testResults

# Unpack the image file(s) in a disposable cache directory.  This can also be something like /run/usr/1000
cache := ~/.cache/ghidraTest
$(cache):
	mkdir -p $@

# Fetch the image from one of the external repositories.

$(cache)/$(Fedora_riscv_image).xz: | $(cache)
	cd $(cache) && \
	wget -q $(Fedora_riscv_site)/$(Fedora_riscv_image).xz

# The image will have several partitions.  Use guestfish to identify those partitions then guestmount to mount them
# *without* needing root permissions.

# $ guestfish -i ~/.cache/ghidraTest/Fedora-Developer-37-20221130.n.0-nvme.raw.img
#
#Welcome to guestfish, the guest filesystem shell for
#editing virtual machine filesystems and disk images.
#
#Type: ‘help’ for help on commands
#      ‘man’ to read the manual
#      ‘quit’ to quit the shell
#
#Operating system: Fedora Linux 37 (Thirty Seven Prerelease)
#/dev/sda2 mounted on /
#/dev/sda1 mounted on /boot

# Make mount point for boot partition
$(cache)/Fedora_boot:
	mkdir -p $@

# Make mount point for root partition
$(cache)/Fedora_root:
	mkdir -p $@

# Make mount point for x partition
$(cache)/Fedora_x:
	mkdir -p $@

.PHONY: Unmount_all

# This particular image has three partitions of which two are needed
#   We use $(cache)/Fedora_mounted as a coarse flag showing that the partitions are mounted
#   Note: /dev/sda3 is a BTRFS device
$(cache)/Fedora_mounted: $(cache)/$(Fedora_riscv_image) | $(cache)/Fedora_boot $(cache)/Fedora_root
	guestmount -a ~/.cache/ghidraTest/$(Fedora_riscv_image) -m /dev/sda2 --ro $(cache)/Fedora_boot
	guestmount -a ~/.cache/ghidraTest/$(Fedora_riscv_image) -m /dev/sda3:/:subvol=root --ro $(cache)/Fedora_root
	touch $(cache)/Fedora_mounted

Unmount_all:
	guestunmount $(cache)/Fedora_boot
	guestunmount $(cache)/Fedora_root
	rm $(cache)/Fedora_mounted

# The vmlinux kernel is embedded within the vmlinuz self-decompressing executable.  Search for the gzip flag bytes then skip
# to the correct offset
riscv64/kernel/$(Fedora_kernel_decompressed): $(cache)/Fedora_mounted $(cache)/Fedora_boot/$(Fedora_kernel) $(cache)/Fedora_mounted
	dd ibs=1 skip=$(Fedora_kernel_offset) if=$(cache)/Fedora_boot/$(Fedora_kernel) of=/tmp/vmlinux-6.5.4-300.0.riscv64.fc39.riscv64
	gunzip -dcf /tmp/vmlinux-6.5.4-300.0.riscv64.fc39.riscv64 > $@

# system map used to identify functions in kernel
/tmp/ghidra_import_tests/$(Fedora_sysmap): $(cache)/Fedora_mounted $(cache)/Fedora_boot/$(Fedora_sysmap)
	mkdir -p /tmp/ghidra_import_tests
	cp $(cache)/Fedora_boot/$(Fedora_sysmap) /tmp/ghidra_import_tests

# a reasonably comlicated loadable kernel module
riscv64/kernel_mod/igc.ko: $(cache)/Fedora_mounted
	xzcat $(cache)/Fedora_root/usr/lib/modules/6.5.4-300.0.riscv64.fc39.riscv64/kernel/drivers/net/ethernet/intel/igc/igc.ko.xz > $@

# a shared library, full of useful symbols and PIC code
riscv64/system_lib/libc.so.6: $(cache)/Fedora_mounted
	cp $(cache)/Fedora_root/usr/lib64/libc.so.6 $@

# another shared library, useful in networking
riscv64/system_lib/libssl.so.3.0.8: $(cache)/Fedora_mounted
	cp $(cache)/Fedora_root/usr/lib64/libssl.so.3.0.8 $@

# and a fully linked executable, using those two shared libraries
riscv64/system_executable/ssh: $(cache)/Fedora_mounted
	cp $(cache)/Fedora_root/usr/bin/ssh $@

all_exemplars: riscv64/kernel/$(Fedora_kernel_decompressed) riscv64/kernel_mod/igc.ko \
			 riscv64/system_lib/libc.so.6 riscv64/system_lib/libssl.so.3.0.8 riscv64/system_executable/ssh \
			 $(Toolchain_exemplar_common_logs) \
			 $(Toolchain_exemplar_thead_logs)

# perform all ghidra imports

IMPORT_LOGS:= riscv64/system_lib/libc.log riscv64/system_lib/libssl.log riscv64/system_executable/ssh.log \
				riscv64/kernel_mod/igc.log riscv64/kernel/vmlinux.log
all_imports: $(IMPORT_LOGS) $(TestResultsDir)/igc_ko_tests.json

clean_imports:
	rm -f $(cache)/Fedora_mounted
	rm -f $(foreach f,$(IMPORT_LOGS),$(f))
	rm -f $(TestResultsDir)/igc_ko_tests.json

# run each exemplar through Ghidra analysis

riscv64/system_lib/libc.log: riscv64/system_lib/libc.so.6
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_lib/libc.so.6 > $@ 2>&1

riscv64/system_lib/libssl.log: riscv64/system_lib/libssl.so.3.0.8
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_lib/libssl.so.3.0.8 > $@ 2>&1

riscv64/system_executable/ssh.log: riscv64/system_executable/ssh
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_executable/ssh > $@ 2>&1

riscv64/kernel_mod/igc.log $(TestResultsDir)/igc_ko_tests.json: riscv64/kernel_mod/igc.ko
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/kernel_mod/igc.ko \
		-scriptPath "$(CurrentDir)/riscv64/java" \
		-postScript IgcTests.java \
		$(TestResultsDir)/igc_ko_tests.json \
		> riscv64/kernel_mod/igc.log 2>&1

riscv64/kernel/vmlinux.log: riscv64/kernel/$(Fedora_kernel_decompressed) /tmp/ghidra_import_tests/$(Fedora_sysmap)
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/kernel/$(Fedora_kernel_decompressed) \
		-processor RISCV:LE:64:RV64IC  \
		-scriptPath $(CurrentDir)/riscv64/java \
		-preScript KernelImport.java \
		/tmp/ghidra_import_tests/$(Fedora_sysmap) \
		> $@ 2>&1

# toolchain ISA extension exemplars should be imported as well

$(Toolchain_exemplar_logdir):
	mkdir -p $(Toolchain_exemplar_logdir)

$(Toolchain_exemplar_logdir)/x-thead-%.log: $(Toolchain_exemplar_dir)/x-thead-%.o | $(Toolchain_exemplar_logdir)
	$(Analyzer) riscv64 exemplars -overwrite -import $< \
	-processor RISCV:LE:64:thead \
	> $@ 2>&1

$(Toolchain_exemplar_logdir)/%.log: $(Toolchain_exemplar_dir)/%.o | $(Toolchain_exemplar_logdir)
	$(Analyzer) riscv64 exemplars -overwrite -import $< \
	-processor RISCV:LE:64:RV64IC  \
	> $@ 2>&1