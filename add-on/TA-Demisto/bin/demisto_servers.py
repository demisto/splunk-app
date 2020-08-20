#!/usr/bin/env python3
#
# This code was written by Demisto Inc
#

import re
import sys
import splunk
import splunk.version as ver
from splunk.rest import BaseRestHandler

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

# Importing the cim_actions demisto_config and demisto_incident libraries
# A.  Import make_splunkhome_path
# B.  Append library path to sys.path
# C.  Import demisto_utils from libraries

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    raise ImportError("Import splunk sub libraries failed\n")

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Demisto", "bin", "lib"]))

try:
    import demisto_utils
except BaseException:
    sys.exit(3)

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

        config = demisto_utils.get_demisto_config_from_response(success, content)

        return config.get('DEMISTOURL', '').strip().split(',')

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
