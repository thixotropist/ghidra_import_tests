Fedora_37_riscv_image := Fedora-Developer-37-20221130.n.0-nvme.raw.img

Analyzer := /opt/ghidra_10.4_DEV/support/analyzeHeadless
Project := Fedora_37_riscv

CurrentDir = $(strip $(shell pwd))

# Unpack the image file in a disposable cache directory.  This can also be something like /run/usr/1000
cache := ~/.cache/ghidraTest
$(cache):
	mkdir -p $@

# Fetch the image from an external repository.

$(Fedora_37_riscv_image): $(cache)
	cd $(cache) && \
	wget -q https://dl.fedoraproject.org/pub/alt/risc-v/repo/virt-builder-images/images/Fedora-Developer-37-20221130.n.0-nvme.raw.img.xz && \
	xz -d $@.xz

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
$(cache)/Fedora_37_boot:
	mkdir -p $@

# Make mount point for root partition
$(cache)/Fedora_37_root:
	mkdir -p $@

.PHONY: Fedora_Mounts Unmount_all all

# This particular image has two needed partitions
Fedora_Mounts: $(cache)/$(Fedora_37_riscv_image) $(cache)/Fedora_37_boot $(cache)/Fedora_37_root
	guestmount -a ~/.cache/ghidraTest/Fedora-Developer-37-20221130.n.0-nvme.raw.img -m /dev/sda1 --ro $(cache)/Fedora_37_boot
	guestmount -a ~/.cache/ghidraTest/Fedora-Developer-37-20221130.n.0-nvme.raw.img -m /dev/sda2 --ro $(cache)/Fedora_37_root

Unmount_all:
	guestunmount $(cache)/Fedora_37_boot
	guestunmount $(cache)/Fedora_37_root

# kernel plus system map
riscv64/kernel/vmlinux-6.0.10-300.0.riscv64.fc37.riscv64:
	gunzip -c -S riscv64 $(cache)/Fedora_37_boot/vmlinuz-6.0.10-300.0.riscv64.fc37.riscv64 > $@
	cp $(cache)/Fedora_37_boot/System.map-6.0.10-300.0.riscv64.fc37.riscv64 riscv64/kernel/

/tmp/ghidra_import_tests/System.map-6.0.10-300.0.riscv64.fc37.riscv64:
	mkdir -p /tmp/ghidra_import_tests
	cp $(cache)/Fedora_37_boot/System.map-6.0.10-300.0.riscv64.fc37.riscv64 /tmp/ghidra_import_tests/System.map-6.0.10-300.0.riscv64.fc37.riscv64

# a reasonably comlicated loadable kernel module
riscv64/kernel_mod/igc.ko:
	xzcat $(cache)/Fedora_37_root/usr/lib/modules/6.0.10-300.0.riscv64.fc37.riscv64/kernel/drivers/net/ethernet/intel/igc/igc.ko.xz > $@

# a shared library, full of useful symbols and PIC code
riscv64/system_lib/libc.so.6:
	cp $(cache)/Fedora_37_root/usr/lib64/libc.so.6 $@

# another shared library, useful in networking
riscv64/system_lib/libssl.so.3.0.5:
	cp $(cache)/Fedora_37_root/usr/lib64/libssl.so.3.0.5 $@

# and a fully linked executable, using those two shared libraries
riscv64/system_executable/ssh:
	cp $(cache)/Fedora_37_root/usr/bin/ssh $@

all_exemplars: riscv64/kernel/vmlinux-6.0.10-300.0.riscv64.fc37.riscv64 riscv64/kernel_mod/igc.ko \
			 riscv64/system_lib/libc.so.6 riscv64/system_lib/libssl.so.3.0.5 riscv64/system_executable/ssh

# perform all ghidra imports

IMPORT_LOGS:= riscv64/system_lib/libc.log riscv64/system_lib/libssl.log riscv64/system_executable/ssh.log \
				riscv64/kernel_mod/igc.log riscv64/kernel/vmlinux.log
all_imports: $(IMPORT_LOGS)

clean_imports:
	rm $(foreach f,$(IMPORT_LOGS),$(f))

# run each exemplar through Ghidra analysis

riscv64/system_lib/libc.log:
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_lib/libc.so.6 > $@ 2>&1

riscv64/system_lib/libssl.log:
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_lib/libssl.so.3.0.5 > $@ 2>&1

riscv64/system_executable/ssh.log:
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/system_executable/ssh > $@ 2>&1

riscv64/kernel_mod/igc.log:
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/kernel_mod/igc.ko \
		-scriptPath "$(CurrentDir)/riscv64/java" \
		-postScript IgcTests.java \
		/tmp/igc_ko_tests.json \
		> $@ 2>&1

riscv64/kernel/vmlinux.log: /tmp/ghidra_import_tests/System.map-6.0.10-300.0.riscv64.fc37.riscv64
	$(Analyzer) riscv64 exemplars -overwrite -import riscv64/kernel/vmlinux-6.0.10-300.0.riscv64.fc37.riscv64 \
		-processor RISCV:LE:64:RV64IC  \
		-scriptPath $(CurrentDir)/riscv64/java \
		-preScript KernelImport.java \
		> $@ 2>&1