#!/usr/bin/python3
"""
Import exemplars into Ghidra
"""
import unittest
import subprocess
import sys
import os
import logging

class Ghidra():
    """
    Collect Ghidra headless analyzer commands.  Ghindra imports are
    sent to the `exemplars` project in the *parent* directory.
    """
    GHIDRA_HOME = "/opt/ghidra_11.1_DEV"
    GHIDRA_RUN = GHIDRA_HOME + "/support/analyzeHeadless"

    def __init__(self, work_dir, script_path='scripts'):
        """
        Ghidra's analyzeHeadless runs in this directory,
        importing riscv-64 binaries with optional postAnalysis
        scripts
        """

        self.work_dir = work_dir
        self.script_path = f"{self.work_dir}/{script_path}"
        self.logger = logging.getLogger('Ghidra')
        stream_handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(stream_handler)
        self.logger.setLevel(logging.INFO)
        #self.logger.setLevel(logging.WARN)

    def import_binary(self, binary_path, pre_script='', post_script='',
                      script_args='', processor='RISCV:LE:64:RV64IC'):
        """
        Perform the headless import, collecting return codes, stderr, and stdout
        as part of the subprocess Result returned object
        """
        command = [Ghidra.GHIDRA_RUN,
                   os.path.dirname(self.work_dir),
                   'riscv64/exemplars',
                   '-processor', processor,
                   '-scriptPath', self.script_path,
                   '-overwrite',
                   '-import', f"{self.work_dir}/{binary_path}"
                   ]
        if pre_script:
            command = command + ['-preScript', pre_script]
        if post_script:
            command = command + ['-postScript', post_script]
        if script_args:
            command = command + [script_args,]
        self.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            self.logger.error("Ghidra import failed:\n %s", result.stderr)
        return result

class T0RiscvImports(unittest.TestCase):
    """
    Import external and internal RISCV exemplars
    """
    workdir = os.getcwd() + '/riscv64'
    ghidra = Ghidra(workdir, 'java')
    test_results_dir = os.getcwd() + '/testResults'

    # kernel ans system map
    kernel_file = 'kernel/vmlinux-6.5.4-300.0.riscv64.fc39.riscv64'
    kernel_path = workdir + '/' + kernel_file
    kernel_import_log_path = kernel_path + '.log'
    sysmap_file = 'kernel/System.map-6.5.4-300.0.riscv64.fc39.riscv64'
    sysmap_path = workdir + '/' + sysmap_file
    kernel_preanalysis_script = 'KernelImport.java'
    kernel_preanalysis_script_path = ghidra.script_path +  '/' + kernel_preanalysis_script

    kernel_module_file = 'kernel_mod/igc.ko'
    kernel_module_path = workdir + '/' + kernel_module_file
    kernel_module_log_path = kernel_module_path + '.log'
    kernel_module_postanalysis_script = 'IgcTests.java'
    kernel_module_postanalysis_script_path = ghidra.script_path +  '/' + kernel_module_postanalysis_script

    def test_00_no_current_lock(self):
        """
        Search for any existing Ghidra instance that might have a lock on our project.
        """
        self.assertFalse(os.path.exists(self.workdir + '/exemplars.lock'),
                        "Close the existing Ghidra instance before continuing")

    def test_01_kernel_import(self):
        """
        Use the Ghidra analyzeHeadless utility to import a RISCV-64 kernel, relocating
        it and merging symbol names from the associated system map.
        """
        kernel_exists = os.path.exists(self.kernel_path)
        map_exists = os.path.exists(self.sysmap_path)
        self.assertTrue(kernel_exists,
                        "Unable to find the RISCV kernel to import into Ghidra")
        self.assertTrue(map_exists,
                        "Unable to find the RISCV kernel sysmap to merge symbol names")
        if not (kernel_exists and map_exists):
            return

        # determine if the kernel was modified more recently than the previous import
        kernel_mod_time = os.path.getmtime(self.kernel_path)
        map_mod_time = os.path.getmtime(self.sysmap_path)
        log_mod_time = os.path.getmtime(self.kernel_import_log_path) \
            if os.path.exists(self.kernel_import_log_path) else 0.0

        if log_mod_time < max(kernel_mod_time, map_mod_time):
            self.ghidra.logger.info('Kernel import needs to be refreshed')
            result = self.ghidra.import_binary(self.kernel_file,
                                    pre_script=self.kernel_preanalysis_script,
                                    script_args=self.sysmap_path)
            with open(self.kernel_import_log_path,'w', encoding='utf-8') as f:
                f.write(result.stdout)
        else:
            self.ghidra.logger.info('Current Kernel import log file found - skipping import')

    def test_02_kernel_module_import(self):
        """
        Import a kernel module and run a post-analysis script to extract relocation values
        for later testing.
        """

        module_exists = os.path.exists(self.kernel_module_path)
        self.assertTrue(module_exists,
                        "Unable to find the RISCV kernel module to import into Ghidra")
        test_script_exists = os.path.exists(self.kernel_module_postanalysis_script_path)
        self.assertTrue(test_script_exists,
                        "Unable to find the RISCV kernel module Ghidra import test script")
        if not (module_exists and test_script_exists):
            return

        # determine if we need a fresh import
        module_mod_time = os.path.getmtime(self.kernel_module_path)
        test_script_mod_time = os.path.getmtime(self.kernel_module_postanalysis_script_path)
        log_mod_time = os.path.getmtime(self.kernel_module_log_path) \
            if os.path.exists(self.kernel_module_log_path) else 0.0
        if log_mod_time < max(module_mod_time, test_script_mod_time):
            self.ghidra.logger.info('Kernel module import needs to be refreshed')
            result = self.ghidra.import_binary(self.kernel_module_file,
                                    post_script=self.kernel_module_postanalysis_script,
                                    script_args=self.test_results_dir + '/igc_ko_tests.json')
            with open(self.kernel_module_log_path,'w', encoding='utf-8') as f:
                f.write(result.stdout)

if __name__ == '__main__':
    unittest.main()
