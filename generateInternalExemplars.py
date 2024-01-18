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