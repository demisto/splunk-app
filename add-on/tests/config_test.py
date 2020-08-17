#!/usr/bin/env python3
# coding=utf-8

#
# This code was written by Demisto Inc
#

import sys
import re
import splunk.version as ver

# Importing the demisto_config library
# A.  Import make_splunkhome_path
# B.  Append library path to sys.path
# C.  Import DemistoConfig from demisto_config

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    raise ImportError("Import splunk sub libraries failed\n")

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Demisto", "bin", "lib"]))

try:
    from demisto_config import DemistoConfig
except BaseException:
    sys.exit(3)


def test_config():
    assert 1 == 1


def test_config_good():
    assert 2 == 2


def test_config_bad():
    assert 2 == 1

