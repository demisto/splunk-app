#!/usr/bin/env python

#
# This code was written by Demisto Inc
#

import json
import re
import splunk.admin as admin
import splunk.rest
import requests

from demisto_config import DemistoConfig

from splunk.clilib import cli_common as cli

# Logging configuration
maxbytes = 200000000

SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"
PORT_REGEX = "^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
IP_REGEX = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
DOMAIN_REGEX = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"

logger = DemistoConfig.get_logger("DEMISTOSETUP")
demisto = DemistoConfig(logger)


class ConfigApp(admin.MConfigHandler):
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['AUTHKEY', 'DEMISTOURL', 'PORT', 'SSL_CERT_LOC', 'HTTPS_PROXY']:
                self.supportedArgs.addOptArg(arg)

    def get_app_password(self):
        password = ""
        try:
            r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT, self.getSessionKey(), method='GET', getargs={
                'output_mode': 'json'})
            if 200 <= int(r[0]["status"]) < 300:
                dict_data = json.loads(r[1])
                if len(dict_data["entry"]) > 0:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto":
                            password = ele["content"]["clear_password"]
                            break

        except Exception as e:
            logger.exception("Exception while retrieving app password. The error was: " + str(e))

            post_args = {
                'severity': 'error',
                'name': 'Demisto',
                'value': 'Exception while retrieving app password. error is: ' + str(e)
            }
            splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                      postargs=post_args)
            raise Exception("Exception while retrieving app password. error is: " + str(e))

        return password

    @staticmethod
    def log_bad_request_details(r):
        """
        logs the details of a bad request

        :param r: request object
        """
        logger.info("Response status code: " + str(r.status_code))
        logger.info("Request headers: " + str(r.request.headers))
        logger.info("Response Details: " + json.dumps(r.json()))
        logger.info("History: " + str(r.history))
        logger.info("Headers: " + str(r.headers))
        logger.info("Cookies: " + str(requests.utils.dict_from_cookiejar(r.cookies)))
        logger.info("URL: " + str(r.url))
        logger.info("Links: " + str(r.links))

    def validate_network(self, url, verify_cert, ssl_cert_loc=None, proxies=None):
        """
        This method is used to validate network connectivity with Demisto. It takes three arguments:

        :param proxies: proxies
        :param url: Demisto URL, its mandatory parameter.
        :param verify_cert: If SSC is to be used
        :param ssl_cert_loc: Location of the public key of the SSC
        :return:
        """
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        try:
            logger.info("In validate network, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(ssl_cert_loc))
            if ssl_cert_loc is None:
                response = requests.get(url=url, verify=verify_cert, allow_redirects=True, headers=headers,
                                        proxies=proxies)
            else:
                response = requests.get(url=url, verify=ssl_cert_loc or True,
                                        allow_redirects=True, headers=headers, proxies=proxies)

            logger.info("Network Validation Status:" + str(response.status_code))
            if 200 <= response.status_code < 300 and len(response.content) > 0:
                return True, response

            # in case of an unsuccessful request - log all of the request details
            logger.info("network was not successfully validated, we may have a connectivity issue")
            self.log_bad_request_details(response)

            raise Exception('Network validation failed. There\'s a connectivity issue with Demisto, please check your '
                            "network settings. Got status: " + str(response.status_code) + ' with the following '
                            'response: ' + json.dumps(response.json()))

        except requests.exceptions.SSLError as err:
            raise Exception('Network validation failed because of SSL validation error. In case you use self-signed '
                            'certificate refer to Demisto\'s manual. Got the following error: ' + str(err))

    def validate_token(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """
        This method is used to validate Authorization token. It takes four arguments:

        :param proxies: proxies
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

        try:
            logger.info("In validate token, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(ssl_cert_loc))

            if ssl_cert_loc is None:
                response = requests.get(url=url, verify=verify_cert, allow_redirects=True, headers=headers,
                                        proxies=proxies)
            else:
                response = requests.get(url=url, verify=ssl_cert_loc or True,
                                        allow_redirects=True, headers=headers, proxies=proxies)

            logger.info("Token Validation Status:" + str(response.status_code))
            if 200 <= response.status_code < 300 and len(response.content) > 0:
                return True, response

            # in case of an unsuccessful request - log all of the request details
            logger.info("Demisto\'s token was not successfully validated")
            self.log_bad_request_details(response)

            raise Exception(
                'Demisto token validation failed, please check that you have the correct token. Got status: '
                + str(response.status_code) + ' with the following response: ' + json.dumps(response.json()))

        except requests.exceptions.SSLError as err:
            raise Exception('Token validation failed because of SSL validation error. In case you use self-signed '
                            'certificate refer to Demisto\'s manual. Got the following error: ' + str(err))

    def validate_permissions(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """
        This method is used to validate that the user have sufficient permissions in Demisto. It takes four arguments:

        :param proxies: proxies
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

        try:
            logger.info("In validate permissions, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(ssl_cert_loc))

            if ssl_cert_loc is None:
                response = requests.get(url=url, verify=verify_cert, allow_redirects=True, headers=headers,
                                        proxies=proxies)
            else:
                response = requests.get(url=url, verify=ssl_cert_loc or True,
                                        allow_redirects=True, headers=headers, proxies=proxies)

            logger.info("Permissions Validation Status:" + str(response.status_code))
            if 200 <= response.status_code < 300 and len(response.content) > 0:
                return True, response

            # in case of an unsuccessful request - log all of the request details
            logger.info(
                "User don't have sufficient permissions in Demisto. Please check that you are working with " +
                "the correct user and contact Demisto support."
            )
            self.log_bad_request_details(response)

            raise Exception("Permissions validation failed. User don't have sufficient permissions in Demisto. "
                            "Please check that you are working with the correct user and contact Demisto support."
                            "got status: " + str(response.status_code) + ' with the following response: ' + json.dumps(
                                response.json()))

        except requests.exceptions.SSLError as err:
            raise Exception(
                'Permissions validation failed because of SSL validation error. In case you use self-signed '
                'certificate refer to Demisto\'s manual. Got the following error: ' + str(err))

    def validate_demisto_connection(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """
        This method is used to validate all aspects of connection with Demisto. It takes four arguments:

        :param proxies: proxies
        :param url: Demisto URL, its mandatory parameter.
        :param authkey: authkey for authentication.
        :param verify_cert: If SSC is to be used
        :param ssl_cert_loc: Location of the public key of the SSC
        :return:
        """
        network_url = url + "/proxyMode"
        self.validate_network(network_url, verify_cert=verify_cert, ssl_cert_loc=ssl_cert_loc, proxies=proxies)

        token_url = url + "/incidenttype"
        self.validate_token(token_url, authkey, verify_cert=verify_cert, ssl_cert_loc=ssl_cert_loc, proxies=proxies)

        permissions_url = url + "/user"
        self.validate_permissions(permissions_url, authkey, verify_cert=verify_cert, ssl_cert_loc=ssl_cert_loc,
                                  proxies=proxies)

    def handleList(self, confInfo):
        config_dict = self.readConf("demistosetup")
        logger.debug("config dict is : " + json.dumps(config_dict))
        for stanza, settings in config_dict.items():
            for key, val in settings.items():
                confInfo[stanza].append(key, val)

    '''
    After user clicks Save on setup screen, take updated parameters,
    normalize them, and save them
    '''

    def handleEdit(self, confInfo):

        password = ''

        if self.callerArgs.data['SSL_CERT_LOC'][0] is None:
            self.callerArgs.data['SSL_CERT_LOC'] = ''

        if self.callerArgs.data['PORT'][0] is None:
            self.callerArgs.data['PORT'] = ''

        elif not re.match(PORT_REGEX, self.callerArgs.data['PORT'][0]):
            logger.exception("Invalid Port Number")
            raise Exception("Invalid Port Number")

        if self.callerArgs.data['AUTHKEY'][0] is None:
            self.callerArgs.data['AUTHKEY'] = ''
        else:
            logger.info("Auth key found")
            password = self.callerArgs.data['AUTHKEY'][0]

        proxies = {}

        if self.callerArgs.data['HTTPS_PROXY'][0] is None:
            self.callerArgs.data['HTTPS_PROXY'] = ''
        else:
            proxies['https'] = self.callerArgs.data['HTTPS_PROXY'][0]

        logger.debug("caller args are: " + json.dumps(self.callerArgs.data))

        if not re.match(IP_REGEX, self.callerArgs.data['DEMISTOURL'][0]) and not \
                re.match(DOMAIN_REGEX, self.callerArgs.data['DEMISTOURL'][0]):
            logger.exception("Invalid URL")
            raise Exception("Invalid URL")

        # checking if the user instructed not to use SSL - development environment scenario
        # getting the current configuration from Splunk
        get_args = {
            'output_mode': 'json',
        }
        success, content = splunk.rest.simpleRequest(CONFIG_ENDPOINT, self.getSessionKey(), method='GET', getargs=get_args)

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

        validate_ssl = config.get('VALIDATE_SSL', True)

        if validate_ssl == 0 or validate_ssl == "0":
            validate_ssl = False
        else:
            validate_ssl = True

        try:
            url = "https://" + self.callerArgs.data['DEMISTOURL'][0]

            if len(self.callerArgs.data['PORT']) > 0 and self.callerArgs.data['PORT'][0] is not None:
                url += ":" + self.callerArgs.data['PORT'][0]

            '''
                Check connectivity with Demisto to verify that the configuration is correct.
                Store the configuration only if it was successful.
            '''
            if self.callerArgs.data['SSL_CERT_LOC']:
                self.validate_demisto_connection(url, password,
                                                 verify_cert=validate_ssl,
                                                 ssl_cert_loc=self.callerArgs.data['SSL_CERT_LOC'][0],
                                                 proxies=proxies)
            else:
                self.validate_demisto_connection(url, password, verify_cert=validate_ssl, proxies=proxies)

            post_args = {
                'severity': 'info',
                'name': 'Demisto',
                'value': 'Demisto connection was successfully validated for host ' +
                         self.callerArgs.data['DEMISTOURL'][0]
            }
            splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                      postargs=post_args)
            user_name = "demisto"
            password = self.get_app_password()

            '''
            Store password into passwords.conf file. There are several scenarios:
            1. Enter credentials for first time, use REST call to store it in passwords.conf
            2. Update password. Use REST call to update existing password.
            3. Update Username. Delete existing User entry and insert new entry.
            '''
            if password:
                post_args = {
                    "password": self.callerArgs.data['AUTHKEY'][0],
                    "output_mode": 'json'
                }
                try:
                    r = splunk.rest.simpleRequest(
                        SPLUNK_PASSWORD_ENDPOINT + "/TA-Demisto%3Ademisto%3A",
                        self.getSessionKey(), postargs=post_args, method='POST')
                    logger.debug("response from app password end point in handleEdit for updating the password is :" + str(r))
                except splunk.AuthorizationFailed:
                    raise Exception(
                        'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                        'user has admin permissions and advice with your Splunk admin')
            else:
                logger.info("Password not found, setting a new password")
                post_args = {
                    "name": user_name,
                    "password": self.callerArgs.data['AUTHKEY'][0],
                    "realm": "TA-Demisto",
                    "output_mode": 'json'
                }
                try:
                    r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT,
                                                  self.getSessionKey(), postargs=post_args, method='POST')
                    logger.debug("response from app password end point for setting a new password in handleEdit is :" +
                                 str(r))
                except splunk.AuthorizationFailed:
                    raise Exception(
                        'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                        'user has admin permissions and advice with your Splunk admin')

            '''
                Remove AUTHKEY from custom configuration.
            '''
            del self.callerArgs.data['AUTHKEY']

            logger.debug("caller args in demisto setup are: " + json.dumps(self.callerArgs.data))
            self.writeConf('demistosetup', 'demistoenv', self.callerArgs.data)
            logger.info("Demisto's Add-on setup was successful")

        except Exception as e:
            logger.exception("Exception while setting up Demisto Add-on, perhaps something is wrong with your "
                             "credentials. The error was: " + str(e))

            post_args = {
                'severity': 'error',
                'name': 'Demisto',
                'value': 'Error happened while setting up Demisto Add-on, perhaps something is wrong with your '
                         'credentials. The error was: ' + str(e)
            }
            splunk.rest.simpleRequest('/services/messages', self.getSessionKey(),
                                      postargs=post_args)
            raise Exception("Error happened while setting up Demisto Add-on , error was: " + str(e))

    def handleReload(self, confInfo=None):
        """
        Handles refresh/reload of the configuration options
        """


# initialize the handler
if __name__ == '__main__':
    admin.init(ConfigApp, admin.CONTEXT_APP_AND_USER)
