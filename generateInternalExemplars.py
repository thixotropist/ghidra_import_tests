#!/usr/bin/python3
"""
Generate small exemplars from source code and imported toolchains
"""
import unittest
import subprocess
import sys
import os
import logging
from shutil import copyfile

class Bazel():
    """
    Collect Bazel build system commands, options, and possibly tests.
    Available options:
    * 'no_bazelrc' : Ignore the contents of the local `.bazelrc`
    * 'output_base': all artifacts are generated here, likely a RAMFS
    * 'distdir': a local cache directory for Bazel components,
    * 'toolchain_resolution': enable platform to toolchain resolution,
    * 'bzlmod': import external BzlMod modules like glog and gtest,
    * 'no_pic': disable Position Independent Code generation
    * 'save_temps': save temporary files generated during compilation, e.g., assembly source code
    * 'show': show how each object is generated
    * 'resolution_debug': debug platform to toolchain resolution
    * 'opt': compile with optimization,
    * 'dbg': compile with debugging symbols

    Common Bazel invocations:

    * `BUILD_HOST` build on the host computer with the host's default platform and toolchain
    * `BUILD_PLATFORM` build on the host computer with an explicit, imported platform and toolchain
    """

    options = {
        'no_bazelrc' : "--noworkspace_rc",
        'output_base': f"--output_base=/run/user/{os.getuid()}/bazel",
        'distdir': "--distdir=/opt/bazel/distdir",
        'toolchain_resolution': "--incompatible_enable_cc_toolchain_resolution",
        'bzlmod': "--experimental_enable_bzlmod",
        'no_pic': "--features=-supports_pic",
        'save_temps': "--save_temps",
        'show': "-s",
        'resolution_debug': "--=toolchain_resolution_debug\'.*\'",
        'opt': "--compilation_mode=opt",
        'dbg': "--compilation_mode=dbg",
        # add an early 7.0.0 bazel workaround
        'hack': "--incompatible_sandbox_hermetic_tmp=false"
    }
    # a successful build is reported with this string
    BUILD_SUCCESS_PATTERN = 'Build completed successfully'

    # Define common bazel build and test commands here
    #   be careful with the separating spaces here - we need exactly one blank between options
    BASE_COMMAND = f"bazel {options['no_bazelrc']} {options['output_base']}"
    BUILD_HOST = BASE_COMMAND + f" build {options['distdir']}"
    BUILD_PLATFORM = BASE_COMMAND + f" build {options['distdir']} {options['toolchain_resolution']}"
    TEST_HOST = BASE_COMMAND + \
        f" test {options['distdir']} {options['toolchain_resolution']} {options['bzlmod']}"

    # The default risc-v 64 bit platform, roughly tracking an SiFive SDK
    DEFAULT_RISCV64_PLATFORM = '//platforms:riscv_userspace'

    # A RISCV-64 platform with support for vector and other mainstream extensions.
    # This likely includes gcc-14 and binutils libraries not yet formally released
    VECTOR_RISCV64_PLATFORM = '//platforms:riscv_vector'

    # A RISCV-64 platform supporting vendor-specific extensions
    VENDOR_EXTENSION_RISCV64_PLATFORM = '//platforms:riscv_custom'

    # An x86_64 platform
    DEFAULT_X86_64_PLATFORM = '//platforms:x86_64_default'

    # a bazel-generated platform representing the local development system
    LOCAL_HOST_PLATFORM = '@local_config_platform//:host'

    def __init__(self, workspace_subdir="riscv64/toolchain"):

        self.logger = logging.getLogger('Bazel')
        stream_handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(stream_handler)
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.WARN)
        self.workspace_dir = f"{os.getcwd()}/{workspace_subdir}"

    def execute(self, platform, target, operation='build', mode='dbg'):
        """
        Build a target with the given platform using toolchain resolution
        """
        command = ['bazel',                                 # invoke bazel
                    Bazel.options['no_bazelrc'],            #   ignoring .bazelrc
                    Bazel.options['output_base'],           #   with output redirected
                    operation,                              # request a build or a test
                    Bazel.options['distdir'],               #   into a local distribution cache
                    Bazel.options['toolchain_resolution'],  #   enabling platform resolution
                    Bazel.options['bzlmod'],                #     and bzlmod imports
                    Bazel.options['hack'],                  #   hack to permit builds in a tmpfs
                    f'--compilation_mode={mode}',           #   choosing debug or optimized
                    Bazel.options['save_temps'],            #   keeping intermediate files
                    f'--platforms={platform}',              #   naming the target platform
                    target                                  # of this Bazel target
                    ]
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command, cwd=self.workspace_dir,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result
    
    def query(self, query_text):
        """
        Run a bazel query
        """
        command = ['bazel', 'query', query_text]
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command, cwd=self.workspace_dir,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result

class Toolchain():
    """ 
    We would like at least four user process C and C++ toolchains:
    * a riscv64 toolchain matching the deployment instruction set, system root,
    *    and base library set.
    * a local host toolchain for checking basic C and C++ syntax or
    *    generating locally-executed tools
    * a riscv64 toolchain aligned with unreleased gcc, binutils, and libraries
    *    to get experience with newer features like riscv intrinsics and autovectorization

    Toolchain testing needs exemplars combining:
    * C and C++ sources
    * simple compile, compile and collect to a library, compile and link to an ELF executable
    * debug and optimized compilation
    * build for deployment on a RISC-V 64 bit CPU and for testing on an x86_64 CI server
    * various dependencies, such as a custom RISC-V libstdc++ and an imported Bazel Module
    *    like googletest or glog

    The biggest challenges in toolchain debugging tend to involve linking and loading, where
    `gcc` or `g++` implicitly invokes `collect2`, `ld`, `ar`, and various linker scripts.
    It is very hard to prove that these implicit dependencies are taken from the imported
    toolchain and not from the host linker environment.  The dynamic libraries (`.so`) needed
    for toolchain executables can be a similar headache.
    """

    # Bazel targets used to test the toolchain environment
    REFERENCE_C_PGM = 'userSpaceSamples:helloworld'
    REFERENCE_CPP_PGM = 'userSpaceSamples:helloworld++'

class T0BazelEnvironment(unittest.TestCase):
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
        result = self.bazel.execute(Bazel.LOCAL_HOST_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.LOCAL_HOST_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

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
        result = self.bazel.execute(Bazel.DEFAULT_RISCV64_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            'bazel {Bazel.DEFAULT_RISCV64_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        object_file = f'{self.objDir}/helloworld/helloworld.pic.o'
        self.bazel.logger.info(f"Running: file {object_file}")
        result = subprocess.run(['file', object_file], cwd=self.bazel.workspace_dir,
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{Bazel.DEFAULT_RISCV64_PLATFORM} compilation generated an unexpected object file format')

    def test_04_riscv64_cpp_build(self):
        """
        riscV64 C++ build of helloworld++, with checks to see if a compatible toolchain was
        invoked
        """
        result = self.bazel.execute(Bazel.DEFAULT_RISCV64_PLATFORM, Toolchain.REFERENCE_CPP_PGM, operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.DEFAULT_RISCV64_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        object_file = f'{self.objDir}/helloworld++/helloworld.pic.o'
        self.bazel.logger.info(f"Running: file {object_file}")
        result = subprocess.run(['file', object_file], cwd=self.bazel.workspace_dir,
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{Bazel.DEFAULT_RISCV64_PLATFORM} compilation generated an unexpected object file format' )

class T1AssemblyExemplars(unittest.TestCase):
    """
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
        cls.bazel = Bazel()
        # fully linked executables end up here
        cls.binDir = 'bazel-bin/userSpaceSamples'
        # object files (*.o) end up here
        cls.objDir = f'{cls.binDir}/_objs'

    def test_00_riscv64_assembly_exemplars(self):
        """
        generate a tarball of assembly instruction exemplars.  This tarball will have four layers of Bazel
        directories to remove when unpacking
        """
        result = self.bazel.execute(Bazel.VENDOR_EXTENSION_RISCV64_PLATFORM, 'assemblySamples:archive', operation='build')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.VENDOR_EXTENSION_RISCV64_PLATFORM} build of assemblySamples:archive failed')

    def test_01_riscv64_assembly_archive(self):
        """
        verify that the generated tarball exists and extract it into the riscv64 exemplar library.
        Nothing in the exemplars directory should be executable, on any platform
        """
        exemplar_tarball = f"{self.bazel.workspace_dir}/bazel-out/k8-fastbuild/bin/assemblySamples/archive.tar"
        self.assertTrue(os.path.exists(exemplar_tarball), "assembly language tarball is missing")
        command = f'cd riscv64/exemplars && tar --strip-components=4 -xf {exemplar_tarball}' + ' && chmod a-x *.{o,objdump,list}'
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8', shell=True,)
        if result.returncode != 0:
            self.logger.error("Extraction of assembly archive failed:\n %s", result.stderr)


if __name__ == '__main__':
    unittest.main()
