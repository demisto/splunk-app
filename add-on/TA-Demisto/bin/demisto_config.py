import json
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
import csv
import gzip
import re
import urllib

import splunk.rest
import requests
from requests import Request
from splunk.clilib import cli_common as cli
import splunk.version as ver

version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    raise ImportError("Import splunk sub libraries failed\n")
    # sys.exit(3)

maxbytes = 20000

class DemistoConfig(object):
    def __init__(self):
        pass

    @classmethod
    def get_logger(cls, logger_name):
        log_path = make_splunkhome_path(["var", "log", "demisto"])
        if not (os.path.isdir(log_path)):
            os.makedirs(log_path)

        handler = RotatingFileHandler(os.path.join(log_path + '/demisto.log'), maxBytes=maxbytes, backupCount=20)

        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)

        logger.addHandler(handler)
        return logger


