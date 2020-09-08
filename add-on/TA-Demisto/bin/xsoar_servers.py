#!/usr/bin/env python3
#
# This code was written by Demisto Inc
#

import json
import splunk
from splunk.rest import BaseRestHandler


ACCOUNTS_ENDPOINT = "/servicesNS/nobody/TA-Demisto/admin/TA_Demisto_account/"


class ServerList(BaseRestHandler):
    def __init__(self, *args):
        BaseRestHandler.__init__(self, *args)

    def get_configured_servers(self):
        get_args = {
            'output_mode': 'json'
        }

        success, content = splunk.rest.simpleRequest(ACCOUNTS_ENDPOINT, self.sessionKey, method='GET',
                                                     getargs=get_args)

        conf_dict = json.loads(content)
        servers = []

        if success and conf_dict:
            for entry in conf_dict.get('entry', []):
                entry_content = entry.get('content', {})
                servers.append(entry_content.get('username'))

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
