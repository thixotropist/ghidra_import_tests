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

class T0Fedora37RiscvImage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger('Fedora37Riscv')
        stream_handler = logging.StreamHandler(sys.stdout)
        cls.logger.addHandler(stream_handler)
        cls.logger.setLevel(logging.INFO)
        #cls.logger.setLevel(logging.WARN)
        command = ('make', 'all_imports')
        cls.logger.info("Running: %s", ' '.join(command))
        result = subprocess.run(command,
            check=False, capture_output=True, encoding='utf8')
        if result.returncode != 0:
            cls.logger.error("Fedora37Riscv: make all_imports failed:\n %s", result.stderr)

    def test00IgcKernelModImport(self):
        """
        Verify that postAnalysis tests on igc.ko import all succeeded
        """
        f = open("/tmp/igc_ko_tests.json")
        tests = json.load(f)
        for t in tests:
            self.logger.info("inspecting the %s test", t['description'])
            self.assertTrue(t['passed']=='true',
                            f"{t['description']} : expected {t['expected']} at {t['addr']}" +
                            f" but found {t['observed']}")
        f.close()

if __name__ == '__main__':
    unittest.main()
