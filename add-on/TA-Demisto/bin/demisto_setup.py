#!/usr/bin/env python

#
# This code is written by Demisto Inc

# import your required python modules
import json
import time
import re

import splunk.admin as admin
import splunk.rest

from demisto_alert import createIncident
from demisto_alert import get_logger

# Logging configuration
maxbytes = 2000000

logger = get_logger("DEMISTOSETUP")


class ConfigApp(admin.MConfigHandler):
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['AUTHKEY', 'DEMISTOURL', 'PORT', 'SSC']:
                self.supportedArgs.addOptArg(arg)

    def getstorage_detail(self):
        r = splunk.rest.simpleRequest(
            "/servicesNS/nobody/TA-Demisto/admin/passwords?search=TA-Demisto&output_mode=json",
            self.getSessionKey(), method = 'GET')
        password = ""

        if 200 <= int(r[0]["status"]) <= 300:
            dict_data = json.loads(r[1])
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:

                    if ele["content"]["realm"] == "TA-Demisto":
                        password = ele["content"]["clear_password"]
                        break

        return password

    def handleList(self, confInfo):
        confDict = self.readConf("demistosetup")

        password = self.getstorage_detail()

        for stanza, settings in confDict.items():
            for key, val in settings.items():

                if key in ['SSC']:

                    if val == 'true' or (val is int and int(val) == 0):
                        val = '1'
                    else:
                        val = '0'

                elif key in ['AUTHKEY']:
                    val = password

                confInfo[stanza].append(key, val)

    '''
    After user clicks Save on setup screen, take updated parameters,
    normalize them, and save them somewhere
    '''

    def handleEdit(self, confInfo):

        exceptionRaised = False
        if int(self.callerArgs.data['SSC'][0]) == 1:
            self.callerArgs.data['SSC'][0] = 'true'

        else:
            self.callerArgs.data['SSC'][0] = 'false'

        if self.callerArgs.data['PORT'][0] is None:
            self.callerArgs.data['PORT'] = ''
        elif not re.match("^[0-9]{1,4}[0-5]?$", self.callerArgs.data['PORT'][0]):
            logger.exception("Invalid Port Number")
            raise Exception("Invalid Port Number")

        if self.callerArgs.data['AUTHKEY'][0] is None:
            self.callerArgs.data['AUTHKEY'] = ''

        else:
            logger.info("Auth key found")
            password = self.callerArgs.data['AUTHKEY'][0]

        if not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
                        self.callerArgs.data['DEMISTOURL'][0]) \
                and not re.match("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$",
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
            resp = createIncident(url, password, data = {"incident_name": "Test Incident from Splunk App for Demisto",
                                                         "details": "Test Incident to verify auth key",
                                                         "occured": time.time()},
                                  verify_req = self.callerArgs.data['SSC'][0])
            logger.info(resp.status_code)
            if resp.status_code != 201 and resp.status_code != 200:
                logger.info("In resp.status_code ")
                postargs = {'severity': 'error', 'name': 'Demisto',
                            'value': 'Invalid configuration for Demisto. Sample incident creation failed with ' + str(
                                resp.status_code) + '.  Please update configuration for Splunk-Demisto integration '
                                                    'to work'}

                splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                                              postargs = postargs)
                exceptionRaised = True

                raise Exception("Create Test Incident Failed")
            else:
                user_name = "demisto"
                password = self.getstorage_detail()
                '''
                Store password into passwords.conf file. Following are different scenarios
                1. Enters credentials for first time, use REST call to store it in passwords.conf
                2. Updates password. Use REST call to update existing password.
                3. Upadates Username. Delete existing User entry and insert new entry.
                '''
                if not (not password):

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
        except:
            logger.exception("Exception while createing Test incident")

            '''
                No need to post error if already raised.
            '''
            if not exceptionRaised:
                postargs = {'severity': 'error', 'name': 'Demisto',
                            'value': 'Invalid configuration for Demisto, please update configuration for '
                                     'Splunk-Demisto integration to work'}
                splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                                              postargs = postargs)
            raise Exception("Invalid Configuration")

    def handleReload(self, confInfo = None):
        """
        Handles refresh/reload of the configuration options
        """


# initialize the handler
if __name__ == '__main__':
    admin.init(ConfigApp, admin.CONTEXT_APP_AND_USER)
