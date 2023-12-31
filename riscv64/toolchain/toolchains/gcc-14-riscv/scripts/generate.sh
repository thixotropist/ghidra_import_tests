#!/bin/bash
echo "Remember to check libc.so and other .so files for absolute paths!"
# generate tarball of risc-v toolchain files
mkdir -p /tmp/export && rsync -rav --include-from=riscv.files --delete /opt/riscvx/ /tmp/export/
while read -r item
do
  strip /tmp/export/${item}
done < strip.files
pushd /tmp/export && tar cJf /tmp/risc64_linux_gnu-14.tar.xz . && popd

# generate tarball of x86_64 dynamic libraries needed by that toolchain

mkdir -p /tmp/ldd && rsync -rav --include-from=ldd.files --delete /usr/lib64/ /tmp/ldd
pushd /tmp/ldd && tar cJf /tmp/fedora39_system_libs.tar.xz . && popd
