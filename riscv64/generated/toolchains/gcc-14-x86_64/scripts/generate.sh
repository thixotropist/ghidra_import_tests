#!/bin/bash
echo "Remember to check libc.so and other .so files for absolute paths!"
# generate tarball of x86_64 gcc-14 compiler suite files

mkdir -p /tmp/export
rsync -ravH --include-from=x86_64.files --delete /opt/x86_64/sysroot/ /tmp/export/

while read -r item
do
  strip /tmp/export/${item}
done < strip.files
pushd /tmp/export && tar cJf /tmp/x86_64_linux_gnu-14.tar.xz . && popd

# generate tarball of x86_64 dynamic libraries needed by that compiler suite

mkdir -p /tmp/ldd && rsync -ravH --include-from=ldd.files --delete /usr/lib64/ /tmp/ldd
pushd /tmp/ldd && tar cJf /tmp/fedora40_system_libs.tar.xz . && popd
