diff --git a/config/riscv/meson.build b/config/riscv/meson.build
index 07d7d9da23..f8691bba10 100644
--- a/config/riscv/meson.build
+++ b/config/riscv/meson.build
@@ -43,7 +43,7 @@ vendor_generic = {
         ['RTE_MAX_NUMA_NODES', 2]
     ],
     'arch_config': {
-        'generic': {'machine_args': ['-march=rv64gc']}
+        'generic': {'machine_args': ['-march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbb_zvbc']}
     }
 }
 
diff --git a/config/riscv/riscv64_linux_gcc b/config/riscv/riscv64_linux_gcc
index 5e58781193..9ab6330313 100644
--- a/config/riscv/riscv64_linux_gcc
+++ b/config/riscv/riscv64_linux_gcc
@@ -1,17 +1,18 @@
 [binaries]
-c = ['ccache', 'riscv64-linux-gnu-gcc']
-cpp = ['ccache', 'riscv64-linux-gnu-g++']
-ar = 'riscv64-linux-gnu-ar'
-strip = 'riscv64-linux-gnu-strip'
+c = ['ccache', '/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc']
+cpp = ['ccache', '/opt/riscvx/bin/riscv64-unknown-linux-gnu-g++']
+ar = '/opt/riscvx/bin/riscv64-unknown-linux-gnu-gcc-ar'
+strip = '/opt/riscvx/bin/riscv64-unknown-linux-unknown-gnu-strip'
 pcap-config = ''
 
 [host_machine]
 system = 'linux'
 cpu_family = 'riscv64'
-cpu = 'rv64gc'
+cpu = 'rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbb_zvbc'
 endian = 'little'
 
 [properties]
 vendor_id = 'generic'
 arch_id = 'generic'
 pkg_config_libdir = '/usr/lib/riscv64-linux-gnu/pkgconfig'
+sys_root = '/opt/riscvx/sysroot'
