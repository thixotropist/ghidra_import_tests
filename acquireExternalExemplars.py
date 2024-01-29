#!/usr/bin/python3
"""
Import large binaries, or verify that their cached exemplars exist.
These binaries are extracted from one or more disk images but not
imported into ghidra here.
"""
import unittest
import subprocess
import sys
import os
import logging
from shutil import copyfile

logging.basicConfig(level=logging.WARN)
logger = logging

GHIDRA_VERSION = "11.1_DEV"
FEDORA_RISCV_SITE = "http://fedora.riscv.rocks/kojifiles/work/tasks/6900/1466900"
FEDORA_RISCV_IMAGE = "Fedora-Developer-39-20230927.n.0-sda.raw"
FEDORA_KERNEL = "vmlinuz-6.5.4-300.0.riscv64.fc39.riscv64"
FEDORA_KERNEL_OFFSET = 40056
FEDORA_KERNEL_DECOMPRESSED = "vmlinux-6.5.4-300.0.riscv64.fc39.riscv64"
FEDORA_SYSMAP = "System.map-6.5.4-300.0.riscv64.fc39.riscv64"
Analyzer = f"/opt/ghidra_{GHIDRA_VERSION}/support/analyzeHeadless"

Current_Dir = os.getcwd()
TestResults_Dir = f"{Current_Dir}/testResults"
Cache_Dir = f"{os.path.expanduser('~')}/.cache/ghidraTest"

class T0SetupDirectories(unittest.TestCase):
    """
    Verify that the directories we need exist or can be created
    """

    def is_writable(self, directory):
        """
        Verify or create a writable results directory
        """
        if os.path.exists(directory):
            is_writable = os.access(directory, os.W_OK)
            self.assertTrue(is_writable,
                            f"Required directory {directory} is not writable!")
            if is_writable:
                return True
            sys.exit()
        else:
            os.makedirs(directory)
            return True

    def is_readable(self, directory):
        """
        Verify or create a readable directory
        """
        if os.path.exists(directory):
            is_readable = os.access(directory, os.R_OK)
            self.assertTrue(is_readable,
                            f"Required directory {directory} is not readable!")
            if is_readable:
                return True
            sys.exit()
        else:
            os.makedirs(directory)
            return True

    def test_00_cache_dir_exists(self):
        """
        The cache directory holds disk images downloaded from the public Internet
        """
        logger.info("Looking for a writable %s", Cache_Dir)
        self.assertTrue(self.is_writable(Cache_Dir))

    def test_01_test_results_dir_exists(self):
        """
        The test results directory holds Ghidra import logs we will need later
        """
        logger.info("Looking for a writable %s", TestResults_Dir)
        self.assertTrue(self.is_writable(TestResults_Dir))

    def test_02_mount_points_exist(self):
        """
        The cache directory needs mount points for disk image partitions.
        These can be created read/write but will be read-only after mounting
        """
        boot_dir = f"{Cache_Dir}/Fedora_boot"
        logger.info("looking for a mount point %s", boot_dir)
        self.is_readable(boot_dir)
        root_dir = f"{Cache_Dir}/Fedora_root"
        logger.info("looking for a mount point %s", root_dir)
        self.is_readable(root_dir)

class T1DiskImages(unittest.TestCase):
    """
    Verify that the cache contains any imported disk images we may need
    """

    def test_00_fedora_image_exists(self):
        """
        Verify that we have a decompressed Fedora disk image present in the cache,
        or retrieve the image and decompress it.
        """
        if os.path.exists(f"{Cache_Dir}/{FEDORA_RISCV_IMAGE}"):
            logger.info("Found the required decompressed Fedora disk image")
            return
        logger.info("Downloading Fedora disk image")

        command = ["wget", "-q", f"{FEDORA_RISCV_SITE}/{FEDORA_RISCV_IMAGE}.xz"]
        result = subprocess.run(command,
                                cwd=Cache_Dir,
                                check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Downloading Fedora disk image failed\n %s", result.stderr)
        command = ["xz", "-d", f"{FEDORA_RISCV_SITE}/{FEDORA_RISCV_IMAGE}.xz"]
        result = subprocess.run(command,
                                cwd=Cache_Dir,
                                check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Decompressing Fedora disk image failed\n %s", result.stderr)
        self.assertTrue(os.path.exists(f"{Cache_Dir}/{FEDORA_RISCV_IMAGE}"),
                        "Unable to download and decompress Fedora disk image")

    def test_01_fedora_boot_mounted(self):
        """
        mount or verify boot partition using guestmount.
        Note that guestmounts can become stale, requiring a manual guestunmount of the mountpoint
        """
        if os.path.exists(f"{Cache_Dir}/Fedora_boot/grub2"):
            logger.info("Fedora boot partition is mounted")
            return
        logger.info("Mounting Fedora boot partition at %s",f"{Cache_Dir}/Fedora_boot" )
        command = ["guestmount", "-a", f"{Cache_Dir}/{FEDORA_RISCV_IMAGE}",
                   "-m", "/dev/sda2", "--ro", f"{Cache_Dir}/Fedora_boot"]
        result = subprocess.run(command,
                                cwd=Cache_Dir,
                                check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Mounting Fedora boot partition failed!\n %s", result.stderr)

    def test_02_fedora_root_mounted(self):
        """
        mount or verify root partition using guestmount.
        Note that guestmounts can become stale, requiring a manual guestunmount of the mountpoint
        """
        if os.path.exists(f"{Cache_Dir}/Fedora_root/usr"):
            logger.info("Fedora root partition is mounted")
            return
        logger.info("Mounting Fedora root partition at %s",f"{Cache_Dir}/Fedora_root" )
        command = ["guestmount", "-a", f"{Cache_Dir}/{FEDORA_RISCV_IMAGE}",
                   "-m", "/dev/sda3:/:subvol=root", "--ro", f"{Cache_Dir}/Fedora_root"]
        result = subprocess.run(command,
                                cwd=Cache_Dir,
                                check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Mounting Fedora root partition failed!\n %s", result.stderr)

class T2RiscvImports(unittest.TestCase):
    """
    Extract different types of large binaries from the Fedora RISCV-64 system image
    """
    Extraction_Dir = f"{Current_Dir}/riscv64"

    def test_00_setup_directories(self):
        """
        Verify that the receiving directories exist
        """
        kernel_dir = f"{self.Extraction_Dir}/kernel"
        kernel_mod_dir = f"{self.Extraction_Dir}/kernel_mod"
        syslib_dir = f"{self.Extraction_Dir}/system_lib"
        system_executable_dir = f"{self.Extraction_Dir}/system_executable"
        for d in (kernel_dir, kernel_mod_dir, syslib_dir, system_executable_dir):
            if os.path.exists(d) and os.access(d, os.W_OK):
                logger.info("Found %s", d)
            else:
                os.makedirs(d)

    def test_01_kernel(self):
        """
        Extract and decompress the kernel plus its associated system map
        """
        kernel_dir = f"{self.Extraction_Dir}/kernel"
        if os.path.exists(f"{kernel_dir}/{FEDORA_KERNEL}"):
            logger.info("Found the compressed kernel image %s", FEDORA_KERNEL)
        else:
            logger.info("Loading the compressed kernel image from the Fedora boot mount point")
            copyfile(f"{Cache_Dir}/{FEDORA_RISCV_IMAGE}", f"{kernel_dir}/{FEDORA_KERNEL}")
        if os.path.exists(f"{kernel_dir}/{FEDORA_KERNEL_DECOMPRESSED}"):
            logger.info("Found the decompressed kernel image %s", FEDORA_KERNEL_DECOMPRESSED)
        else:
            command = ["dd", "ibs=1", f"skip={FEDORA_KERNEL_OFFSET}",
                       f"if={kernel_dir}/{FEDORA_KERNEL}",
                       f"of={kernel_dir}/{FEDORA_KERNEL_DECOMPRESSED}.gz"]
            result = subprocess.run(command,
                                check=False, capture_output=True, encoding='utf8')
            if result.returncode != 0:
                logger.error("Extracting Fedora compressed kernel failed!\n %s", result.stderr)
                self.fail("Extracting Fedora compressed kernel failed!")
                return
            command = ["gunzip", "-df", "--quiet", f"{kernel_dir}/{FEDORA_KERNEL_DECOMPRESSED}.gz"]
            result = subprocess.run(command,
                                check=False, capture_output=True, encoding='utf8')
            # ignore warnings about trailing garbage
            if result.returncode == 1:
                logger.error("Decompressing Fedora compressed kernel failed!\n %s",
                                  result.stderr)
                self.fail("Decompressing Fedora compressed kernel failed!")

        # copy the kernel system map next to the kernel
        # TODO: check to see if the kernel file is newer
        if os.path.exists(f"{kernel_dir}/{FEDORA_SYSMAP}"):
            logger.info("Found Fedora kernel system map")
        else:
            logger.info("Copying Fedora kernel system map")
            map_path = f"{Cache_Dir}/Fedora_boot/{FEDORA_SYSMAP}"
            map_exists = os.path.exists(map_path)
            self.assertTrue(map_exists,
                            f"Failed to locate System map at {map_path}")
            if not map_exists:
                return
            copyfile(map_path, f"{kernel_dir}/{FEDORA_SYSMAP}")

    def test_02_kernel_module(self):
        """
        A reasonably complicated loadable kernel module
        """
        kernel_mod_source = f"{Cache_Dir}/Fedora_root/usr/lib/modules/6.5.4-300.0.riscv64.fc39.riscv64/kernel/drivers/net/ethernet/intel/igc/igc.ko.xz"
        kernel_mod_destination = f"{self.Extraction_Dir}/kernel_mod/igc.ko"
        if os.path.exists(kernel_mod_destination):
            logger.info("Found the compressed kernel module %s", kernel_mod_destination)
        else:
            logger.info("Copying kernel module")
            command = f"xzcat {kernel_mod_source} > {kernel_mod_destination}"
            result = subprocess.run(command,
                                check=False, capture_output=True, encoding='utf8', shell=True)
            if result.returncode != 0:
                logger.error("Decompressing kernel module failed!\n %s", result.stderr)
                self.fail("Decompressing kernel module failed!")

    def test_03_system_libraries(self):
        """
        Several common system libraries
        """
        source = f"{Cache_Dir}/Fedora_root/usr/lib64/libc.so.6"
        destination = f"{self.Extraction_Dir}/system_lib/libc.so.6"
        if os.path.exists(destination):
            logger.info("Found the libc.so system library")
        else:
            logger.info("Copying system library libc.so")
            copyfile(source, destination)

        source = f"{Cache_Dir}/Fedora_root/usr/lib64/libssl.so.3.0.8"
        destination = f"{self.Extraction_Dir}/system_lib/libssl.so.3.0.8"
        if os.path.exists(destination):
            logger.info("Found the libssl.so system library")
        else:
            logger.info("Copying the libssl.so system library")
            copyfile(source, destination)

    def test_04_system_executable(self):
        """
        A common system executable
        """
        source = f"{Cache_Dir}/Fedora_root/usr/bin/ssh"
        destination = f"{self.Extraction_Dir}/system_executable/ssh"
        if os.path.exists(destination):
            logger.info("Found the ssh system executable")
        else:
            logger.info("Copying ssh system executable")
            copyfile(source, destination)

if __name__ == '__main__':
    unittest.main()
