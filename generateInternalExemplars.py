#!/usr/bin/python3
"""
Generate exemplars from source code and imported toolchains
"""
import unittest
import subprocess
import os
import logging
from shutil import copyfile
from bazel import Bazel
from toolchain import Toolchain

logging.basicConfig(level=logging.INFO)
logger = logging

class T0BazelEnvironment(unittest.TestCase):
    """
    wrap invocations of the Bazel environment
    """
    @classmethod
    def setUpClass(cls):
        """
        Initialize a toolchain test environment
        """
        cls.bazel = Bazel()
        # fully linked executables end up here
        cls.binDir = 'bazel-bin/'
        # object files (*.o) end up here
        cls.objDir = f'{cls.binDir}/_objs'

    def test_01_local_helloworld(self):
        """
        local host toolchain (x86_64) build of helloworld.  Assumes we have gcc installed
        locally, so we are mostly exercising a minimal Bazel environment
        """
        result = self.bazel.execute(Toolchain.LOCAL_HOST_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.LOCAL_HOST_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

    def test_02_verify_platforms(self):
        """
        Search Bazel workspace for key platforms
        """
        result = self.bazel.query("//riscv64/generated/platforms:*")

        self.assertRegex(result.stdout, r'riscv64_default',
                         "riscv64 default platform is defined")
        self.assertRegex(result.stdout, r'riscv64_rva23',
                         "riscv64 rva23 profile platform is defined")
        self.assertRegex(result.stdout, r'riscv64_thead',
                         "riscv64 THead user space platform is defined")

    def test_03_riscv64_build(self):
        """
        riscV64 C build of helloworld, with checks to see if a compatible toolchain was
        invoked.  This test assumes that the local host version of `file` can
        recognize riscv-64 object files.
        """
        platform = Toolchain.DEFAULT_RISCV64_PLATFORM
        result = self.bazel.execute(platform, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {platform} build of {Toolchain.REFERENCE_C_PGM} failed')

        executable_file = f'{self.binDir}/riscv64/generated/userSpaceSamples/helloworld'
        logger.info(f"Running: file {executable_file}")
        result = subprocess.run(['file', executable_file],
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB executable, UCB RISC-V',
            f'//platforms:{platform} compilation generated an unexpected executable file format')

    def test_04_riscv64_cpp_build(self):
        """
        riscV64 C++ build of helloworld++, with checks to see if a compatible toolchain was
        invoked
        """
        platform = Toolchain.DEFAULT_RISCV64_PLATFORM
        result = self.bazel.execute(platform, Toolchain.REFERENCE_CPP_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {platform} build of {Toolchain.REFERENCE_C_PGM} failed')

        executable_file = f'{self.binDir}/riscv64/generated/userSpaceSamples/helloworld++'
        logger.info(f"Running: file {executable_file}")
        result = subprocess.run(['file', executable_file],
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB executable, UCB RISC-V',
            f'//platforms:{platform} compilation generated an unexpected executable file format' )

class T1IsaExemplars(unittest.TestCase):
    """
    Gather exemplars likely invoking instruction set extensions.

    The binutils gas testsuite includes many assembly language exemplars.
    These are imported into the workspace, then assembled with a default
    riscv64 gcc toolchain - each with whatever architecture declaration is needed
    for the instructions to be recognized.  The exemplars include vector,
    bit manipulation, crypto, cache control, and vendor-specific instructions.
    For each assembly source file we generate an object file, an assembly listing file,
    and a dump of that object file using a compatible objdump utility.
    The dump file shows us the reference disassembly for the object file,
    and gives us something to compare with the Ghidra disassembly.
    """
    @classmethod
    def setUpClass(cls):
        """
        Initialize a toolchain test environment
        """
        cls.bazel = Bazel()

    def test_00_riscv64_assembly_exemplars(self):
        """
        Generate a tarball of assembly instruction exemplars.
        This tarball will have four layers of Bazel
        directories to remove when unpacking
        """
        platform = Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM
        result = self.bazel.execute(platform,
                                            '//riscv64/generated/assemblySamples:archive',
                                            operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {platform} build of assemblySamples:archive failed')

        # Verify that the generated tarball exists and extract it into the riscv64 exemplar library.
        # Nothing in the exemplars directory should be executable, on any platform
        exemplar_tarball = "bazel-bin/riscv64/generated/assemblySamples/archive.tar"
        self.assertTrue(os.path.exists(exemplar_tarball), "assembly language tarball is missing")
        command = f'tar -xf {exemplar_tarball} --strip-components=6 -C riscv64/exemplars' + \
            ' && chmod a-x riscv64/exemplars/*.{o,objdump,list}'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True)
        self.assertEqual(0, result.returncode,
            f'unable to unpack {exemplar_tarball} into the exemplar directory')
        if result.returncode != 0:
            logger.error("Extraction of assembly archive failed:\n %s", result.stderr)

    def test_01_riscv64_gcc_expansions(self):
        """
        Generate exemplars showing how gcc expands memory copy operations
        into extension instruction sequences
        """
        platform = Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM
        result = self.bazel.execute(platform, '//riscv64/generated/gcc_expansions:archive',
                                    operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {platform} build of gcc_expansions:archive failed')
        exemplar_tarball = "bazel-bin/riscv64/generated/gcc_expansions/archive.tar"
        command = f'tar -xf {exemplar_tarball} --strip-components=6 -C riscv64/exemplars'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True)
        self.assertEqual(0, result.returncode,
            f'unable to unpack {exemplar_tarball} into the exemplar directory')
        if result.returncode != 0:
            logger.error("Extraction of gcc_expansions archive failed:\n %s", result.stderr)

    @unittest.skip("this throws a gcc floating point exception")
    def test_02_whisper_app_default(self):
        """
        Build the whisper.cpp app for the basic riscv64 platforms
        """

        # bazel generated exemplars are read-only, so we need to remove older
        # exemplars before continuing
        command = 'cd riscv64/exemplars && rm -f whisper_cpp*'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Cleanup of previous whisper_cpp exemplars failed:\n %s", result.stderr)

        # we want to build the target with and without stripping symbols
        build_targets = ['@whisper_cpp//:main', '@whisper_cpp//:main.stripped']

        result = self.bazel.execute(Toolchain.DEFAULT_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.DEFAULT_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main",
                 "riscv64/exemplars/whisper_cpp_default")
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main.stripped",
                 "riscv64/exemplars/whisper_cpp_default_stripped")

        result = subprocess.run(['readelf', '-A', 'riscv64/exemplars/whisper_cpp_vendor'],
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Unable to extract whisper_cpp_vendor attributes:\n %s", result.stderr)
        self.assertRegex(result.stdout, r'xtheadba', 'Whisper vendor build did not enable THead extensions')

    def test_02_whisper_app_rva23(self):
        """
        Build the whisper.cpp app for a more advanced rva23 platform
        """

        # bazel generated exemplars are read-only, so we need to remove older
        # exemplars before continuing
        command = 'cd riscv64/exemplars && rm -f whisper_cpp*'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Cleanup of previous whisper_cpp exemplars failed:\n %s", result.stderr)

        # we want to build the target with and without stripping symbols
        build_targets = ['@whisper_cpp//:main', '@whisper_cpp//:main.stripped']

        result = self.bazel.execute(Toolchain.VECTOR_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.VECTOR_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main",
                 "riscv64/exemplars/whisper_cpp_rva23")
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main.stripped",
                 "riscv64/exemplars/whisper_cpp_rva23_stripped")

        result = subprocess.run(['readelf', '-A', 'riscv64/exemplars/whisper_cpp_rva23'],
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Unable to extract whisper_cpp_vector attributes:\n %s", result.stderr)
        self.assertRegex(result.stdout, r'_v1p', 'Whisper vector build did not enable rva23 extensions')

    def test_02_whisper_app_thead(self):
        """
        Build the whisper.cpp app for a custom THead platform
        """

        # bazel generated exemplars are read-only, so we need to remove older
        # exemplars before continuing
        command = 'cd riscv64/exemplars && rm -f whisper_cpp*'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Cleanup of previous whisper_cpp exemplars failed:\n %s", result.stderr)

        # we want to build the target with and without stripping symbols
        build_targets = ['@whisper_cpp//:main', '@whisper_cpp//:main.stripped']
        result = self.bazel.execute(Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.DEFAULT_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main",
                "riscv64/exemplars/whisper_cpp_vendor")
        copyfile("bazel-bin/external/+_repo_rules+whisper_cpp/main.stripped",
                "riscv64/exemplars/whisper_cpp_vendor_stripped")

        result = subprocess.run(['readelf', '-A', 'riscv64/exemplars/whisper_cpp_vendor'],
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            logger.error("Unable to extract whisper_cpp_default attributes:\n %s", result.stderr)
        self.assertRegex(result.stdout, r'_xtheadba', 'Whisper THead build failed to include any THead extensions')

    def test_03_x86_64_toolchains(self):
        """
        Verify x86_64 C and C++ toolchains with a helloworld build
        """
        result = self.bazel.execute(Toolchain.DEFAULT_X86_64_PLATFORM,
                                    '//x86_64/generated/userSpaceSamples:helloworld',
                                    operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.DEFAULT_X86_64_PLATFORM} C toolchain test failed')
        result = self.bazel.execute(Toolchain.DEFAULT_X86_64_PLATFORM,
                                    '//x86_64/generated/userSpaceSamples:helloworld++',
                                    operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.DEFAULT_X86_64_PLATFORM} C++ toolchain test failed')

    def test_04_x86_64_vector_exemplars(self):
        """
        Generate reference x86_64 exemplars showing vectorization for different architectures
        """
        result = self.bazel.execute(Toolchain.DEFAULT_X86_64_PLATFORM,
                                    '//x86_64/generated/gcc_vectorization:archive',
                                    operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.DEFAULT_X86_64_PLATFORM} build of gcc_vectorization:archive failed')
        exemplar_tarball = "bazel-bin/x86_64/generated/gcc_vectorization/archive.tar"
        command = f'tar -xf {exemplar_tarball} --strip-components=6 ' + \
            '-C x86_64/exemplars && chmod a-x x86_64/exemplars/*'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        self.assertEqual(0, result.returncode,
            f'unable to unpack {exemplar_tarball} into the x86_64 exemplar directory')
        if result.returncode != 0:
            logger.error("Extraction of x86_64 gcc_vectorization archive failed:\n %s",
                         result.stderr)

if __name__ == '__main__':

    unittest.main()
