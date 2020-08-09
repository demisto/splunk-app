#!/usr/bin/env python3
#
# This code was written by Demisto Inc
#

import json
import splunk
from splunk.rest import BaseRestHandler

CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"


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

        servers = config.get('DEMISTOURL', '').strip().split(',')

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
