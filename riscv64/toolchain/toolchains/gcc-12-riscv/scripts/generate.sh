#!/bin/bash

# generate tarball of risc-v toolchain files
mkdir -p /tmp/export && rsync -rav --include-from=riscv.files --delete /opt/riscv/ /tmp/export/
while read -r item
do
  strip /tmp/export/${item}
done < strip.files
pushd /tmp/export && tar cJf /tmp/risc64_linux_gnu-12.tar.xz . && popd

# generate tarball of x86_64 dynamic libraries needed by that toolchain

mkdir -p /tmp/ldd && rsync -rav --include-from=ldd.files --delete /lib64 /tmp/ldd
pushd /tmp/ldd && tar cJf /tmp/fedora38_system_libs.tar.xz . && popd
