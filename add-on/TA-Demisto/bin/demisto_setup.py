#!/usr/bin/env python

#
# This code is written by Demisto Inc

# import your required python modules
import json
import re
import splunk.admin as admin
import splunk.rest

from demisto_alert import get_logger
from demisto_alert import validate_token

# Logging configuration
maxbytes = 2000000

logger = get_logger("DEMISTOSETUP")


class ConfigApp(admin.MConfigHandler):
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['AUTHKEY', 'DEMISTOURL', 'PORT', 'SSL_CERT_LOC']:
                self.supportedArgs.addOptArg(arg)

    def getstorage_detail(self):
        r = splunk.rest.simpleRequest(
            "/servicesNS/nobody/TA-Demisto/admin/passwords?search=TA-Demisto&output_mode=json",
            self.getSessionKey(), method = 'GET')
        password = ""

        if 200 <= int(r[0]["status"]) < 300:
            dict_data = json.loads(r[1])
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:

                    if ele["content"]["realm"] == "TA-Demisto":
                        password = ele["content"]["clear_password"]
                        break

        return password

    def handleList(self, confInfo):
        confDict = self.readConf("demistosetup")

        for stanza, settings in confDict.items():
            for key, val in settings.items():
                confInfo[stanza].append(key, val)

    '''
    After user clicks Save on setup screen, take updated parameters,
    normalize them, and save them somewhere
    '''

    def handleEdit(self, confInfo):

        exceptionRaised = False


        if self.callerArgs.data['SSL_CERT_LOC'][0] is None:
            self.callerArgs.data['SSL_CERT_LOC'] = ''

        if self.callerArgs.data['PORT'][0] is None:
            self.callerArgs.data['PORT'] = ''
        elif not re.match("^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", self.callerArgs.data['PORT'][0]):
            logger.exception("Invalid Port Number")
            raise Exception("Invalid Port Number")

        if self.callerArgs.data['AUTHKEY'][0] is None:
            self.callerArgs.data['AUTHKEY'] = ''

        else:
            logger.info("Auth key found")
            password = self.callerArgs.data['AUTHKEY'][0]

        if not re.match(
                "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
                self.callerArgs.data['DEMISTOURL'][0]) \
                and not re.match(
                        "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$",
                        self.callerArgs.data['DEMISTOURL'][0]):
            logger.exception("Invalid URL")
            raise Exception("Invalid URL")

        try:

            url = "https://" + self.callerArgs.data['DEMISTOURL'][0]

            if len(self.callerArgs.data['PORT']) > 0 and self.callerArgs.data['PORT'][0] is not None:
                url += ":" + self.callerArgs.data['PORT'][0]

            '''
                Create Test Incident to demisto to verify if the configuration entered are correct
                Store configuration only if create incident was successful.
            '''
            url += "/incidenttype"
            if self.callerArgs.data['SSL_CERT_LOC']:
                valid, status = validate_token(url, password,
                                       verify_cert = True,
                                       ssl_cert_loc = self.callerArgs.data['SSL_CERT_LOC'][0])
            else:
                valid, status = validate_token(url, password, verify_cert = True)

            if not valid:
                logger.info("resp status: " + str(status))
                postargs = {'severity': 'error', 'name': 'Demisto',
                            'value': 'Token validation Failed, got status: ' + str(status)
                            }

                splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                          postargs = postargs)
                exceptionRaised = True

                raise Exception('Token validation Failed, got status: ' + str(status))
            else:
                postargs = {'severity': 'info', 'name': 'Demisto',
                            'value': 'Demisto API key was successfully validated for host ' +self.callerArgs.data['DEMISTOURL'][0]
                            }

                splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                          postargs = postargs)
                user_name = "demisto"
                password = self.getstorage_detail()
                '''
                Store password into passwords.conf file. Following are different scenarios
                1. Enters credentials for first time, use REST call to store it in passwords.conf
                2. Updates password. Use REST call to update existing password.
                3. Upadates Username. Delete existing User entry and insert new entry.
                '''
                if password:
                    postArgs = {
                        "password": self.callerArgs.data['AUTHKEY'][0]
                    }
                    logger.info("In UPDATE")
                    realm = "TA-Demisto:" + user_name + ":"
                    splunk.rest.simpleRequest(
                        "/servicesNS/nobody/" + self.appName + "/admin/passwords/" + realm + "?output_mode=json",
                        self.getSessionKey(), postargs = postArgs, method = 'POST')

                else:
                    logger.info("Password not found")
                    postArgs = {
                        "name": user_name,
                        "password": self.callerArgs.data['AUTHKEY'][0],
                        "realm": "TA-Demisto"
                    }
                    splunk.rest.simpleRequest("/servicesNS/nobody/TA-Demisto/admin/passwords/?output_mode=json",
                                              self.getSessionKey(), postargs = postArgs, method = 'POST')

                '''
                    Remove AUTHKEY from custom configuration.
                '''
                del self.callerArgs.data['AUTHKEY']

                self.writeConf('demistosetup', 'demistoenv', self.callerArgs.data)
        except Exception as e:
            logger.exception("Exception while createing Test incident, error: " + str(e))
            
            postargs = {'severity': 'error', 'name': 'Demisto',
                        'value': 'Invalid configuration for Demisto, please update configuration for '
                                 'Splunk-Demisto integration to work, error is: ' + str(e)}
            splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                      postargs = postargs)
            raise Exception("Invalid Configuration, error: " + str(e))

    def handleReload(self, confInfo = None):
        """
        Handles refresh/reload of the configuration options
        """


# initialize the handler
if __name__ == '__main__':
    admin.init(ConfigApp, admin.CONTEXT_APP_AND_USER)
