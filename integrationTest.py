#!/usr/bin/python3
"""
Exercise binary import processes, collecting assertion tests
"""

import unittest
import sys
import os
import logging
import json

class T0FedoraRiscvImage(unittest.TestCase):
    """
    Apply proof of concept tests to results of disk image import
    """

    @classmethod
    def setUpClass(cls):
        cls.logger = logging.getLogger('FedoraRiscv')
        stream_handler = logging.StreamHandler(sys.stdout)
        cls.logger.addHandler(stream_handler)
        cls.logger.setLevel(logging.INFO)
        #cls.logger.setLevel(logging.WARN)

        cls.testResultsDir = os.getcwd() + "/testResults"

    def test_00_igc_kernel_mod_import(self):
        """
        Verify that postAnalysis tests on igc.ko import all succeeded
        """
        json_results_file_name = self.testResultsDir +"/igc_ko_tests.json"
        file_exists = os.path.exists(json_results_file_name)
        self.assertTrue(file_exists,
                        "Json test results file from igc_ko import exists")
        if file_exists:
            with open(json_results_file_name, 'r', encoding='utf-8') as f:
                tests = json.load(f)
            for t in tests:
                self.logger.info("inspecting the %s test", t['description'])
                self.assertEqual(t['passed'], 'true',
                                f"{t['description']} : expected {t['expected']} at {t['addr']}" +
                                f" but found {t['observed']}")

if __name__ == '__main__':
    unittest.main()
