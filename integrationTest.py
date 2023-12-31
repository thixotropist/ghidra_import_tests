#!/usr/bin/python3
"""
Exercise binary import processes, collecting assertion tests
"""

import unittest
import subprocess
import re
import sys
import os
import logging
import json

class T0FedoraRiscvImage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger('FedoraRiscv')
        stream_handler = logging.StreamHandler(sys.stdout)
        cls.logger.addHandler(stream_handler)
        cls.logger.setLevel(logging.INFO)
        #cls.logger.setLevel(logging.WARN)
        command = ('make', 'all_imports')
        cls.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            cls.logger.error("FedoraRiscv: make all_imports failed:\n %s", result.stderr)
        cls.testResultsDir = os.getcwd() + "/testResults"

    def test00IgcKernelModImport(self):
        """
        Verify that postAnalysis tests on igc.ko import all succeeded
        """
        jsonResultsFileName = self.testResultsDir +"/igc_ko_tests.json"
        fileExists = os.path.exists(jsonResultsFileName)
        self.assertTrue(fileExists,
                        "Json test results file from igc_ko import exists")
        if fileExists:
            f = open(jsonResultsFileName)
            tests = json.load(f)
            for t in tests:
                self.logger.info("inspecting the %s test", t['description'])
                self.assertTrue(t['passed']=='true',
                                f"{t['description']} : expected {t['expected']} at {t['addr']}" +
                                f" but found {t['observed']}")
            f.close()

if __name__ == '__main__':
    unittest.main()
