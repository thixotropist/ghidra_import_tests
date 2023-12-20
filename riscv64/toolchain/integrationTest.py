#!/usr/bin/python3
"""
Generate crossplatform binaries for use in Ghidra testing.  Start with riscv64 binaries
generated by gcc-12 C and C++ compilers, possibly adding some assembly source code to
emulate other environments.  These are imported into Ghidra with optional postAnalysis
scripts run to provide integration tests.

"""

import unittest
import subprocess
import re
import sys
import os
import logging
import json

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
    * `TEST_HOST` run integration tests on the host computer with a CI product emulation platform

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

    # The risc-v 64 bit platform assumed for a notional network appliance
    PRODUCT_PLATFORM = '//platforms:riscv_userspace'
    # The x86_64 server platform used for integration testing, including mocks for risc-v components
    CI_PLATFORM = '//platforms:x86_64_userspace'
    # a bazel-generated platform representing the local development system
    LOCAL_HOST_PLATFORM = '@local_config_platform//:host'

    def __init__(self):

        self.logger = logging.getLogger('Bazel')
        stream_handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(stream_handler)
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.WARN)

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
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result

class Toolchain():
    """ 
    We would like at least three user process C and C++ toolchains:
    * a riscv64 toolchain matching the deployment instruction set, system root,
    *    and base library set.
    * an x86_64 toolchain used by the Continuous Integration test server,
    *    ideally with identical versions of gcc, glib, etc.
    * an optional local host toolchain for checking basic C and C++ syntax or
    *    generating locally-executed tools

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

class Ghidra():
    """
    Collect Ghidra headless analyzer commands.  Ghindra imports are
    sent to the `exemplars` project in the *parent* directory.
    """
    GHIDRA_HOME = "/opt/ghidra_10.5_DEV"
    GHIDRA_RUN = GHIDRA_HOME + "/support/analyzeHeadless"

    def __init__(self, scriptPath="../java"):
        """
        Ghidra's analyzeHeadless runs in this directory,
        importing riscv-64 binaries with optional postAnalysis
        scripts
        """

        self.workDir = os.getcwd()
        self.scriptPath = f"{self.workDir}/{scriptPath}"
        self.logger = logging.getLogger('Ghidra')
        stream_handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(stream_handler)
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.WARN)

    def import_binary(self, binaryPath, preScript='', postScript='', scriptArgs=''):
        """
        Perform the headless import, collecting return codes, stderr, and stdout
        as part of the subprocess Result returned object
        """
        command = [Ghidra.GHIDRA_RUN,
                   os.path.dirname(self.workDir),
                   'exemplars',
                   '-processor', 'RISCV:LE:64:RV64IC',
                   '-scriptPath', self.scriptPath,
                   '-overwrite',
                   '-import', f"{self.workDir}/{binaryPath}"
                   ]
        if preScript:
            command = command + ['-preScript', preScript]
        if postScript:
            command = command + ['-postScript', postScript]
        if scriptArgs:
            command = command + [scriptArgs,]
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Bazel build failed:\n %s", result.stderr)
        return result

class T0ToolchainTest(unittest.TestCase):
    """
    Test the methods provided by Bazel
    Tests are run in alphanumeric order
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

    @classmethod
    def tearDownClass(cls):
        """
        Nothing to be done, currently
        """
        pass

    def test00VerifyToolchainResolution(self):
        """
        Verify that workspace .bazelrc exists and enables toolchain resolution.
        Toolchain resolution becomes default in Bazel 7, so this test will be unnecessary in time
        """
        self.assertTrue(os.path.exists('./.bazelrc'),
          '.bazelrc file must exist to enable toolchain resolution')
        with open('./.bazelrc', 'r', encoding='utf-8') as bazelrcFile:
            data = bazelrcFile.read()
            self.assertRegex(data, re.escape('build --incompatible_enable_cc_toolchain_resolution'),
              'Workspace .bazelrc file does not enable C/C++ toolchain resolution')

    def test01LocalCHelloWorld(self):
        """
        local host toolchain (x86_64) build of helloworld, 
        """
        result = self.bazel.execute(Bazel.LOCAL_HOST_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.LOCAL_HOST_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

    def test02InitializeToolchain(self):
        """
        Try a continuous integration (x86_64) build, mostly to make sure bazel imports the toolchain
        """
        result = self.bazel.execute(Bazel.CI_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.CI_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

    def test03RiscV64Build(self):
        """
        riscV64 C build of helloworld, with checks to see if the right toolchain was
        invoked.  This test assumes that the local host version of `file` can recognize riscv-64 object files.
        """
        result = self.bazel.execute(Bazel.PRODUCT_PLATFORM, Toolchain.REFERENCE_C_PGM,
                                    operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            'bazel {Bazel.PRODUCT_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        objectFile = f'{self.objDir}/helloworld/helloworld.pic.o'
        self.bazel.logger.info(f"Running: file {objectFile}")
        result = subprocess.run(['file', objectFile],
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{Bazel.PRODUCT_PLATFORM} compilation generated an unexpected object file format')

    def test04RiscV64CppBuild(self):
        """
        riscV64 C++ build of helloworld++, with checks to see if the right toolchain was
        invoked
        """
        result = self.bazel.execute(Bazel.PRODUCT_PLATFORM, Toolchain.REFERENCE_CPP_PGM, operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.PRODUCT_PLATFORM} build of {Toolchain.REFERENCE_C_PGM} failed')

        objectFile = f'{self.objDir}/helloworld++/helloworld.pic.o'
        self.bazel.logger.info(f"Running: file {objectFile}")
        result = subprocess.run(['file', objectFile],
            check=True, capture_output=True, encoding='utf8')
        self.assertRegex(result.stdout, 'ELF 64-bit LSB relocatable, UCB RISC-V',
            f'//platforms:{Bazel.PRODUCT_PLATFORM} compilation generated an unexpected object file format' )

class T1ImportTests(unittest.TestCase):
    """
    Compile and import one or more source files (C, C++, assembly) into Ghidra
    using the Ghidra headless analyzer.  Results are ignored, except for Ghidra return code
    """
    @classmethod
    def setUpClass(cls):
        """
        Initialize a Ghidra environment
        """
        cls.ghidra = Ghidra()
        cls.bazel = Bazel()
        # fully linked executables end up here
        cls.binDir = 'bazel-bin/userSpaceSamples'
        # object files (*.o) end up here
        cls.objDir = f'{cls.binDir}/_objs'

    def test01HelloWorld(self):
        """
        build a riscv-64 helloworld binary and import the executable and object files into Ghidra.
        """

        result = self.bazel.execute(Bazel.PRODUCT_PLATFORM, 'userSpaceSamples:helloworld', operation='build', mode='dbg')
        self.assertEqual(0, result.returncode,
            f'bazel {Bazel.PRODUCT_PLATFORM} build of helloworld failed')

        result = self.ghidra.import_binary(f'{self.binDir}/helloworld')
        self.assertEqual(0, result.returncode,
                         'Ghidra imported userSpaceSamples:helloworld executable built for riscv64')
        result = self.ghidra.import_binary(f'{self.objDir}/helloworld/helloworld.pic.o')
        self.assertEqual(0, result.returncode,
                         'Ghidra imported userSpaceSamples:helloworld pic object file built for riscv64')

class T2RelocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Initialize a Ghidra environment and import one or more test cases into Ghidra
        """
        cls.ghidra = Ghidra()
        cls.bazel = Bazel()
        cls.resultsDir = os.getcwd() + "/testResults"
        cls.build_results = {}
        cls.import_results = {}

        # import the executable
        cls.build_results['executable'] = \
            cls.bazel.execute(Bazel.PRODUCT_PLATFORM, 'userSpaceSamples:relocationTest_pie', operation='build', mode='opt')
        with open(cls.resultsDir + '/relocationTest_pie_build_stdout', 'w', encoding='utf-8') as file:
            file.write(cls.build_results['executable'].stdout)
        with open(cls.resultsDir + '/relocationTest_pie_build_stderr', 'w', encoding='utf-8') as file:
            file.write(cls.build_results['executable'].stderr)

        # import the pie executable, saving stdout and stderr for analysis
        cls.import_results['executable'] = \
            cls.ghidra.import_binary('bazel-bin/userSpaceSamples/relocationTest_pie')
        with open(cls.resultsDir + '/relocationTest_pie_import_stdout', 'w', encoding='utf-8') as file:
            file.write(cls.import_results['executable'].stdout)
        with open(cls.resultsDir + '/relocationTest_pie_import_stderr', 'w', encoding='utf-8') as file:
            file.write(cls.import_results['executable'].stderr)

        # import the pie object file, running an analysis script and saving stdout and stderr for analysis
        cls.import_results['objectfile'] = \
            cls.ghidra.import_binary('bazel-bin/userSpaceSamples/_objs/relocationTest_pie/relocationTest.o',
                                     postScript='RelocationTestImport.java',
                                     scriptArgs=f'{cls.resultsDir}/relocationTest.json')
        with open(cls.resultsDir + '/relocationTest_objectfile_import_stdout', 'w', encoding='utf-8') as file:
            file.write(cls.import_results['objectfile'].stdout)
        with open(cls.resultsDir + '/relocationTest_pie_objectfile_import_stderr', 'w', encoding='utf-8') as file:
            file.write(cls.import_results['objectfile'].stderr)

    def test01ValidateImports(self):
        """
        Check the return codes on all Bazel build and Ghidra imports for success
        """
        self.assertEqual(0, self.build_results['executable'].returncode,
                         f'bazel {Bazel.PRODUCT_PLATFORM} build of relocationTest_pie failed')
        self.assertEqual(0, self.import_results['executable'].returncode,
                         'Ghidra imported userSpaceSamples:relocationTest_pie executable built for riscv64')
        self.assertEqual(0, self.import_results['objectfile'].returncode,
                        'Ghidra imported userSpaceSamples:relocationTest_pie object file built for riscv64')

    def test02GccPcRelRelocations(self):
        """
        Build and import a Gnu C binary that exercises many of the RISC-V 64 bit relocations generated by binutils 2-40.
        Many of these relocation types are erased during linking, so we want to import both executables and objects.  Object files
        vary quite a bit based on compiler options.  Position Independent Code (PIC) is for objects that might be used in a sharable object
        file.  Position Independent Executable (PIE) is more likely found in kernel load modules.
        """
        jsonResultsFileName = self.resultsDir +"/relocationTest.json"
        fileExists = os.path.exists(jsonResultsFileName)
        self.assertTrue(fileExists,
                        "Json test results file from relocationTest import exists")
        if fileExists:
            f = open(jsonResultsFileName)
            tests = json.load(f)
            for t in tests:
                #self.logger.info("inspecting the %s test", t['description'])
                if t['description'].startswith('SKIPPED:'):
                    #self.logger.info("\ SKIPPED!")
                    pass
                else:
                    self.assertTrue(t['passed']=='true',
                                    f"{t['description']} : expected {t['expected']} at {t['addr']}" +
                                    f" but found {t['observed']}")
            f.close()

    @unittest.skip("Relocations to thread Local storage needs support")
    def test03GccTpRelRelocations(self):
        """
        Does Ghidra import thread-local data sections?  The decompiler may need work.
        """
        testlog = self.import_results['objectfile'].stdout
        self.assertRegex(testlog, r'Passed: R_RISCV_TPREL_HI20 at 0x100020')
        self.assertRegex(testlog, r'Passed: R_RISCV_TPREL_LO12_I at 0x100030')
        self.assertRegex(testlog, r'Passed: R_RISCV_TPREL_ADD')

if __name__ == '__main__':
    unittest.main()
