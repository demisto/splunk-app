#
# This code was written by Demisto Inc
#

import os
import logging
from logging.handlers import RotatingFileHandler
import re
import requests
import splunk.version as ver

version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    raise ImportError("Import splunk sub libraries failed\n")

maxbytes = 20000


class DemistoConfig(object):
    def __init__(self, logger):
        self.logger = logger

    @classmethod
    def get_logger(cls, logger_name):
        """
        This method is used to create a logger object

        :param logger_name:
        :return: logger object
        """
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

    def validate_token(self, url, authkey, verify_cert, ssl_cert_loc=None):
        """
        This method is used to validate Authorization token. It takes four arguments:

        :param url: Demisto URL, its mandatory parameter.
        :param authkey: authkey for authentication.
        :param verify_cert: If SSC is to be used
        :param ssl_cert_loc: Location of the public key of the SSC
        :return:
        """
        headers = {
            'Authorization': authkey,
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        if ssl_cert_loc is None:
            # todo remove comments below
            # logger.info("Passing verify = False")
            # r = requests.get(url = url, verify = False,allow_redirects = True, headers = headers)
            self.logger.info("Using " + str(verify_cert) + " value for verify")
            r = requests.get(url=url, verify=verify_cert, allow_redirects=True, headers=headers)
        else:
            self.logger.info("Passing verify=" + str(ssl_cert_loc))
            r = requests.get(url=url, verify=ssl_cert_loc or True,
                             allow_redirects=True, headers=headers)

        self.logger.info("Token Validation Status:" + str(r.status_code))
        if 200 <= r.status_code < 300 and len(r.content) > 0:
            return True, str(r.status_code)

        return False, str(r.status_code)
