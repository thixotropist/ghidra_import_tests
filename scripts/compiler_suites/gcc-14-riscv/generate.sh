#!/bin/bash
echo "Remember to check libc.so and other .so files for absolute paths!"
# generate tarball of risc-v generated files
mkdir -p /tmp/export
rsync -ravH --include-from=files --delete /opt/riscv/sysroot/ /tmp/export/
while read -r item
do
  strip /tmp/export/${item}
done < strip_host.files

while read -r item
do
  /opt/riscv/sysroot/riscv64-unknown-linux-gnu/bin/strip /tmp/export/${item}
done < strip_target.files

rdfind -makehardlinks true -outputname /tmp/rdfind.log /tmp/export
pushd /tmp/export && tar cJf /tmp/risc64_linux_gnu-14.tar.xz . && popd

# generate tarball of x86_64 dynamic libraries needed by that compiler suite
#  Copy host x86_64 files
mkdir -p /tmp/ldd && rsync -ravH --include-from=ldd.files --delete /usr/lib64/ /tmp/ldd
#  Patch loader scripts to avoid absolute paths
cp libc.so libm.so /tmp/ldd
pushd /tmp/ldd && tar cJf /tmp/fedora40_system_libs.tar.xz . && popd
