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
        cls.binDir = 'bazel-bin/userSpaceSamples'
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
        result = self.bazel.query("//platforms:*")

        self.assertRegex(result.stdout, r'riscv_userspace', "riscv64 default user space platform is defined")
        self.assertRegex(result.stdout, r'riscv_vector', "riscv64 vector extension user space platform is defined")
        self.assertRegex(result.stdout, r'riscv_custom', "riscv64 custom  user space platform is defined")

    def test_03_riscv64_build(self):
        """
        riscV64 C build of helloworld, with checks to see if a compatible toolchain was
        invoked.  This test assumes that the local host version of `file` can recognize riscv-64 object files.
        """
        result = self.bazel.execute( Toolchain.DEFAULT_RISCV64_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.DEFAULT_RISCV64_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        object_file = f'{self.objDir}/helloworld/helloworld.pic.o'
        logger.info(f"Running: file {object_file}")
        result = subprocess.run(['file', object_file], cwd=self.bazel.workspace_dir,
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{Toolchain.DEFAULT_RISCV64_PLATFORM} compilation generated an unexpected object file format')

    def test_04_riscv64_cpp_build(self):
        """
        riscV64 C++ build of helloworld++, with checks to see if a compatible toolchain was
        invoked
        """
        result = self.bazel.execute( Toolchain.DEFAULT_RISCV64_PLATFORM, Toolchain.REFERENCE_CPP_PGM, operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Toolchain.DEFAULT_RISCV64_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        object_file = f'{self.objDir}/helloworld++/helloworld.pic.o'
        logger.info(f"Running: file {object_file}")
        result = subprocess.run(['file', object_file], cwd=self.bazel.workspace_dir,
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{ Toolchain.DEFAULT_RISCV64_PLATFORM} compilation generated an unexpected object file format' )

class T1IsaExemplars(unittest.TestCase):
    """
    Gather exemplars likely invoking instruction set extensions.

    The binutils gas testsuite includes many assembly language exemplars.  These are imported into the workspace,
    then assembled with a default riscv64 gcc toolchain - each with whatever architecture declaration is needed
    for the instructions to be recognized.  The exemplars include vector, bit manipulation, crypto, cache control,
    and vendor-specific instructions.  For each assembly source file we generate an object file, an assembly listing file,
    and a dump of that object file using a compatible objdump utility.  The dump file shows us the reference disassembly
    for the object file, and gives us something to compare with the Ghidra disassembly.
    """
    @classmethod
    def setUpClass(cls):
        """
        Initialize a toolchain test environment
        """
        cls.bazel_riscv64 = Bazel(workspace_subdir="riscv64/toolchain")
        cls.bazel_x86_64 = Bazel(workspace_subdir="x86_64/toolchain")

    def test_00_riscv64_assembly_exemplars(self):
        """
        generate a tarball of assembly instruction exemplars.  This tarball will have four layers of Bazel
        directories to remove when unpacking
        """
        result = self.bazel_riscv64.execute( Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM,
                                            'assemblySamples:archive', operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM} build of assemblySamples:archive failed')

        # Verify that the generated tarball exists and extract it into the riscv64 exemplar library.
        # Nothing in the exemplars directory should be executable, on any platform
        exemplar_tarball = f"{self.bazel_riscv64.workspace_dir}/bazel-bin/assemblySamples/archive.tar"
        self.assertTrue(os.path.exists(exemplar_tarball), "assembly language tarball is missing")
        command = f'cd riscv64/exemplars && tar --strip-components=4 -xf {exemplar_tarball}' + \
            ' && chmod a-x *.{o,objdump,list}'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Extraction of assembly archive failed:\n %s", result.stderr)

    def test_01_riscv64_gcc_expansions(self):
        """
        Generate exemplars showing how gcc expands memory copy operations into extension instruction sequences
        """
        result = self.bazel_riscv64.execute(Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM, 'gcc_expansions:archive', operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM} build of gcc_expansions:archive failed')
        exemplar_tarball = f"{self.bazel_riscv64.workspace_dir}/bazel-bin/gcc_expansions/archive.tar"
        command = f'cd riscv64/exemplars && tar --strip-components=4 -xf {exemplar_tarball} */*/*/*/*.so' + ' && chmod a-x *.so'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Extraction of gcc_expansions archive failed:\n %s", result.stderr)

    def test_02_whisper_apps(self):
        """
        Build the whisper.cpp app under multiple architectures
        """

        # bazel generated exemplars are read-only, so we need to remove older exemplars before continuing
        command = 'cd riscv64/exemplars && rm -f whisper_cpp*'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Cleanup of previous whisper_cpp exemplars failed:\n %s", result.stderr)

        # we want to build the target with and without stripping symbols
        build_targets = ['@whisper_cpp//:main', '@whisper_cpp//:main.stripped']

        result = self.bazel_riscv64.execute(Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.VENDOR_EXTENSION_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main",
                 "riscv64/exemplars/whisper_cpp_vendor")
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main.stripped",
                 "riscv64/exemplars/whisper_cpp_vendor_stripped")

        result = self.bazel_riscv64.execute(Toolchain.VECTOR_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.VECTOR_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main",
                 "riscv64/exemplars/whisper_cpp_vector")
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main.stripped",
                 "riscv64/exemplars/whisper_cpp_vector_stripped")

        result = self.bazel_riscv64.execute(Toolchain.DEFAULT_RISCV64_PLATFORM,
                                            build_targets, operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.DEFAULT_RISCV64_PLATFORM} build of @whisper_cpp//:main failed')
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main",
                 "riscv64/exemplars/whisper_cpp_default")
        copyfile(f"{self.bazel_riscv64.workspace_dir}/bazel-bin/external/whisper_cpp/main.stripped",
                 "riscv64/exemplars/whisper_cpp_default_stripped")

    def test_03_x86_64_vector_exemplars(self):
        """
        Generate reference x86_64 exemplars showing vectorization for different architectures
        """
        result = self.bazel_x86_64.execute(Toolchain.DEFAULT_X86_64_PLATFORM, 'gcc_vectorization:archive', operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel { Toolchain.DEFAULT_X86_64_PLATFORM} build of gcc_vectorization:archive failed')
        exemplar_tarball = f"{self.bazel_x86_64.workspace_dir}/bazel-bin/gcc_vectorization/archive.tar"
        command = f'cd x86_64/exemplars && tar --strip-components=4 -xf {exemplar_tarball} */*/*/*/*' + ' && chmod a-x *'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            logger.error("Extraction of x86_64 gcc_vectorization archive failed:\n %s", result.stderr)

if __name__ == '__main__':

    unittest.main()
