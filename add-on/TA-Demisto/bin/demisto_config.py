"""Config script to handle GET requests."""
#
# This code was written by Demisto Inc
#

import os
import logging
from logging.handlers import RotatingFileHandler
import re
import json
import splunk.version as ver
from splunk.rest import BaseRestHandler
import splunk

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    raise ImportError("Import splunk sub libraries failed\n")

MAXBYTES = 2000000


class DemistoConfig(object):
    """Class for Demisto config object used to gather config data out of endpoints."""

    def __init__(self, logger):
        """Init the class by starting a logger."""
        self.logger = logger

    @classmethod
    def get_logger(cls, logger_name):
        """Method is used to create a logger object.

        :param logger_name:
        :return: logger object
        """
        try:
            log_path = make_splunkhome_path(["var", "log", "demisto"])
            if not os.path.isdir(log_path):
                os.makedirs(log_path)

            handler = RotatingFileHandler(
                os.path.join(
                    log_path + '/demisto.log'
                ),
                maxBytes=MAXBYTES,
                backupCount=20
            )

            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler.setFormatter(formatter)
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.INFO)
            logger.addHandler(handler)
            return logger
        except Exception as ex:
            raise ex


class ServerList(BaseRestHandler):
    """Class just to list the servers that are stored in rest."""

    def __init__(self, *args):
        """Init the class."""
        BaseRestHandler.__init__(self, *args)

    def get_configured_servers(self):
        """Use Splunk internal rest for this apo to pull back a list of the saved servers."""
        try:
            get_args = {
                'output_mode': 'json'
            }

            success, content = splunk.rest.simpleRequest(
                CONFIG_ENDPOINT,
                self.sessionKey,
                method='GET',
                getargs=get_args
            )

            conf_dic = json.loads(content)
            config = {}
            if success and conf_dic:
                for entry in conf_dic.get('entry', []):
                    val = entry.get('content', {})
                    if val:
                        config = val
            if '' in config:
                config.pop('')
            if 'config' in config:
                config.pop('config')

            servers = config.get('DEMISTOURL', '').strip().split(',')

            return servers
        except Exception as ex:
            raise ex

    def handle_GET(self):
        """Function just to handle the get request when the app is edited."""
        try:
            servers = self.get_configured_servers()
            return dict([(x, '') for x in servers])

        except splunk.AuthorizationFailed as e:
            raise Exception('Insufficient permissions to retrieve password. Consult your Splunk administrator. Error was: ' + str(e))

        except Exception as e:
            return {
                'error': str(e),
                'status': 400
            }
