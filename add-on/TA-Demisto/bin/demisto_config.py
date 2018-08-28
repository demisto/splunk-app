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

version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    raise ImportError("Import splunk sub libraries failed\n")

maxbytes = 2000000


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


class ServerList(BaseRestHandler):
    def __init__(self, *args):
        BaseRestHandler.__init__(self, *args)

    def get_configured_servers(self):
        get_args = {
            'output_mode': 'json'
        }

        success, content = splunk.rest.simpleRequest(CONFIG_ENDPOINT, self.sessionKey, method='GET',
                                                     getargs=get_args)

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

        servers = config.get('DEMISTOURL', '').split(',')

        return servers

    def handle_GET(self):
        try:
            servers = self.get_configured_servers()
            return dict([(x, '') for x in servers])

        except splunk.AuthorizationFailed as e:
            raise Exception(
                'Insufficient permissions to retrieve password. Consult your Splunk administrator. Error was: '
                + str(e))

        except Exception as e:
            return {
                'error': str(e),
                'status': 400
            }
