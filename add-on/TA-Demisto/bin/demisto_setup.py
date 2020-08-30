"""Demisto setup class used when opening the app to edit."""

from __future__ import absolute_import

#
# This code was written by Demisto Inc
#

import json
import re
import splunk.admin as admin
import splunk.rest
import requests
import hashlib
from demisto_config import DemistoConfig

# Logging configuration
maxbytes = 200000000

SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"
PORT_REGEX = r"^([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
IP_REGEX = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
DOMAIN_REGEX = r"(?i)(?:[-A-Z0-9]+\[?\.\]?)+[-A-Z0-9]+(?::[0-9]+)?(?:(?:\/|\?)[-A-Z0-9+&@#\/%=~_$?!\-:,.\(\);]*[A-Z0-9+&@#\/%=~_$\(\);])?|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
URL_REGEX = r"(?i)(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})"

logger = DemistoConfig.get_logger("DEMISTOSETUP")
demisto = DemistoConfig(logger)


class ConfigApp(admin.MConfigHandler):
    """Class to create a config object."""

    def setup(self):
        """Method to determine which action the use has taken."""
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in [
                'AUTHKEY',
                'DEMISTOURL',
                'PORT',
                'SSL_CERT_LOC',
                'HTTPS_PROXY_ADDRESS',
                'HTTPS_PROXY_USERNAME',
                'HTTPS_PROXY_PASSWORD',
                'EXCLUSION_LIST',
                'BEYOND_CORP_API',
                'BEYOND_CORP_KEY',
                'BEYOND_CORP_SECRET'
            ]:
                self.supportedArgs.addOptArg(arg)

    def get_app_password(self, save_name):
        """Method to call endpoint to retrieve password."""
        password = ""

        try:
            r = splunk.rest.simpleRequest(
                SPLUNK_PASSWORD_ENDPOINT,
                self.getSessionKey(),
                method='GET',
                getargs={
                    'output_mode': 'json',
                    'search': save_name
                }
            )

            if 200 <= int(r[0]["status"]) < 300:
                dict_data = json.loads(r[1])
                if len(dict_data["entry"]) > 0:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto" and \
                                ele["name"] == "TA-Demisto:{}:".format(save_name):
                            password = ele["content"].get("clear_password", '')
                            break
            return password

        except Exception as e:
            logger.exception("Exception while retrieving app password. The error was: " + str(e))
            raise Exception("Exception while retrieving app password. error is: " + str(e))

    def get_proxy_password(self):
        """Method to call endpoint to retrieve proxy password."""
        password = ""
        try:
            r = splunk.rest.simpleRequest(
                SPLUNK_PASSWORD_ENDPOINT,
                self.getSessionKey(),
                method='GET',
                getargs={
                    'output_mode': 'json',
                    'search': 'TA-Demisto-Proxy',
                    'count': 100
                }
            )

            if 200 <= int(r[0]["status"]) < 300:
                dict_data = json.loads(r[1])
                if len(dict_data["entry"]) > 0:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto-Proxy":
                            password = ele["content"]["clear_password"]
                            break
            return password

        except Exception as e:
            logger.exception("Exception while retrieving proxy password. The error was: " + str(e))
            raise Exception("Exception while retrieving proxy password. error is: " + str(e))

    def set_server_password(self, new_password, server):
        """Method to call endpoint to set password."""
        save_name = hashlib.sha1(server).hexdigest()
        current_password = self.get_app_password(save_name)

        # Store password into passwords.conf file. There are several scenarios:
        # 1. Enter credentials for first time, use REST call to store it in passwords.conf
        # 2. Update password. Use REST call to update existing password.

        if current_password:
            post_args = {
                "password": new_password,
                "output_mode": 'json'
            }
            try:
                r = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT + "/TA-Demisto%3A{}%3A".format(save_name),
                    self.getSessionKey(),
                    postargs=post_args,
                    method='POST'
                )
                logger.debug("response from app password end point in handleEdit for updating the password is :" + str(r))
            except splunk.AuthorizationFailed:
                raise Exception(
                    'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                    'user has admin permissions and advice with your Splunk admin')
        else:
            logger.info("Password not found, setting a new password")
            post_args = {
                "name": save_name,
                "password": new_password,
                "realm": "TA-Demisto",
                "output_mode": 'json'
            }
            try:
                r = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT,
                    self.getSessionKey(),
                    postargs=post_args,
                    method='POST'
                )
                logger.debug("response from app password end point for setting a new password in handleEdit is :" + str(r))
            except splunk.AuthorizationFailed:
                raise Exception(
                    'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                    'user has admin permissions and advice with your Splunk admin')

    # BEYONDCORP - function to set BEYONDCORP parameters securely
    def set_beyondcorp_passwords(self, new_key, new_secret):
        """Method to call endpoint to set oauth password."""
        # save_name = hashlib.sha1(server).hexdigest()
        save_name_key = 'TA-Demisto-BeyondCorp-Key'
        save_name_secret = 'TA-Demisto-BeyondCorp-Secret'
        # current_password = self.get_app_password(save_name)
        current_key = self.get_app_password(save_name_key)
        current_secret = self.get_app_password(save_name_secret)

        # Store key and secret in passwords.conf file. There are several scenarios:
        # 1. Enter credentials for first time, use REST call to store it in passwords.conf
        # 2. Update password. Use REST call to update existing password.
        if current_key and current_secret:
            post_args_key = {
                "password": new_key,
                "output_mode": 'json'
            }

            post_args_secret = {
                "password": new_secret,
                "output_mode": 'json'
            }
            try:
                splunk_response = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT +
                    "/TA-Demisto-BeyondCorp%3A{}%3A".format(save_name_key),
                    self.getSessionKey(),
                    postargs=post_args_key,
                    method='POST'
                )
                # LOGGER.info(
                #     "response from BeyondCorp end point in handleEdit " +
                #     "for updating the key is :" + str(splunk_response)
                # )

                splunk_response = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT +
                    "/TA-Demisto-BeyondCorp%3A{}%3A".format(save_name_secret),
                    self.getSessionKey(),
                    postargs=post_args_secret,
                    method='POST'
                )
                # logger.info(
                #     "response from BeyondCorp end point in handleEdit " +
                #     "for updating the secret is :" +
                #     str(splunk_response)
                # )

            except splunk.AuthorizationFailed as ex:
                raise Exception(
                    'User does not have sufficient permissions in Splunk to store ' +
                    'the beyond corp key and secret. Make sure that this '
                    'user has admin permissions' +
                    str(ex)
                )
        else:
            logger.info("Key and secret not found, setting a new values")
            post_args_key = {
                "name": save_name_key,
                "password": new_key,
                "realm": "TA-Demisto-BeyondCorp",
                "output_mode": 'json'
            }

            post_args_secret = {
                "name": save_name_secret,
                "password": new_secret,
                "realm": "TA-Demisto-BeyondCorp",
                "output_mode": 'json'
            }

            try:
                splunk_response = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT,
                    self.getSessionKey(),
                    postargs=post_args_key,
                    method='POST'
                )
                # LOGGER.info(
                #     "response from BeyondCorp end point in handleEdit " +
                #     "for updating the key is : %s",
                #     str(splunk_response)
                # )

                splunk_response = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT,
                    self.getSessionKey(),
                    postargs=post_args_secret,
                    method='POST'
                )
                # LOGGER.info(
                #     "response from BeyondCorp end point in handleEdit " +
                #     "for updating the secret is :" + str(splunk_response)
                # )
            except splunk.AuthorizationFailed as ex:
                raise Exception(
                    'User does not have sufficient permissions in Splunk to store ' +
                    'the beyond corp key and secret. Make sure that this '
                    'user has admin permissions' +
                    str(ex)
                )

    def get_ssl_validation_settings(self):
        """Method to call endpoint to retrieve ssl config."""
        # checking if the user instructed not to use SSL - development environment scenario
        # getting the current configuration from Splunk
        try:
            get_args = {
                'output_mode': 'json'
            }
            success, content = splunk.rest.simpleRequest(
                CONFIG_ENDPOINT,
                self.getSessionKey(),
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

            validate_ssl = config.get('VALIDATE_SSL', True)

            if validate_ssl == 0 or validate_ssl == "0":
                validate_ssl = False
            else:
                validate_ssl = True

            return validate_ssl
        except Exception as ex:
            raise ex

    def get_proxy_settings(self):
        """Method to call endpoint to retrieve proxy config."""
        proxies = {}

        proxy_address, proxy_username, proxy_password = None, None, None
        if self.callerArgs.data['HTTPS_PROXY_ADDRESS'][0] is None:
            self.callerArgs.data['HTTPS_PROXY_ADDRESS'] = ''
        else:
            proxy_address = True
        if self.callerArgs.data['HTTPS_PROXY_USERNAME'][0] is None:
            self.callerArgs.data['HTTPS_PROXY_USERNAME'] = ''
        else:
            proxy_password = True
        if self.callerArgs.data['HTTPS_PROXY_PASSWORD'][0] is None:
            self.callerArgs.data['HTTPS_PROXY_PASSWORD'] = ''
        else:
            proxy_username = True

        if (proxy_address and proxy_username and proxy_password):
            proxy = "https://" + self.callerArgs.data['HTTPS_PROXY_USERNAME'][0] + ":" + \
                    self.callerArgs.data['HTTPS_PROXY_PASSWORD'][0] + "@" + \
                    self.callerArgs.data['HTTPS_PROXY_ADDRESS'][0].split("//")[1]
            proxies['https'] = proxy
        elif (proxy_address and not (proxy_username and proxy_password)):
            proxy = self.callerArgs.data['HTTPS_PROXY_ADDRESS'][0]
            proxies['https'] = proxy

        password = self.get_proxy_password()
        user_name = "demisto"

        # Store password into passwords.conf file. There are several scenarios:
        # 1. Enter credentials for first time, use REST call to store it in passwords.conf
        # 2. Update password. Use REST call to update existing password.
        # 3. Update Username. Delete existing User entry and insert new entry.

        if password:
            post_args = {
                "password": json.dumps(proxies),
                "output_mode": 'json'
            }
            try:
                r = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT + "/TA-Demisto-Proxy%3Ademisto%3A",
                    self.getSessionKey(), postargs=post_args, method='POST'
                )

                logger.debug("response from proxy password end point in handleEdit for updating the proxy password is :" + str(r))
            except splunk.AuthorizationFailed:
                raise Exception(
                    'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                    'user has admin permissions and advice with your Splunk admin')
        elif (not password) and (proxies != {}):
            logger.info("Proxy password not found, setting a new password")
            post_args = {
                "name": user_name,
                "password": json.dumps(proxies),
                "realm": "TA-Demisto-Proxy",
                "output_mode": 'json'
            }
            try:
                r = splunk.rest.simpleRequest(
                    SPLUNK_PASSWORD_ENDPOINT,
                    self.getSessionKey(),
                    postargs=post_args,
                    method='POST'
                )
                logger.debug("response from app password end point for setting a new password in handleEdit is : " + str(r))
            except splunk.AuthorizationFailed:
                raise Exception(
                    'User don\'t have sufficient permissions in Splunk to store the password. Make sure that this '
                    'user has admin permissions and advice with your Splunk admin')

        return proxies

    @staticmethod
    def log_bad_request_details(r):
        """Log the details of a bad request."""
        logger.info("Response status code: " + str(r.status_code))
        logger.info("Response Details: " + json.dumps(r.json()))
        logger.info("History: " + str(r.history))
        # logger.info("Cookies: " + str(requests.utils.dict_from_cookiejar(r.cookies)))
        logger.info("URL: " + str(r.url))
        logger.info("Links: " + str(r.links))

    def validate_network(self, url, verify_cert, ssl_cert_loc=None, proxies=None):
        """Method is used to validate network connectivity with Demisto."""
        # It takes three arguments:

        # :param proxies: proxies
        # :param url: Demisto URL, its mandatory parameter.
        # :param verify_cert: If SSC is to be used
        # :param ssl_cert_loc: Location of the public key of the SSC
        # :return:
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }

        try:
            logger.info("In validate network, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(ssl_cert_loc))
            if ssl_cert_loc is None:
                response = requests.get(
                    url=url,
                    verify=verify_cert,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )
            else:
                response = requests.get(
                    url=url,
                    verify=ssl_cert_loc or True,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )

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

        except requests.exceptions.ProxyError as err:
            raise Exception('Network validation failed because of proxy connection error. Make sure that you entered '
                            'the correct proxy with right credentials. Got the following error: ' + str(err))

    def validate_token(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """Method is used to validate Authorization token.

        It takes four arguments:
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
            logger.info(
                "In validate token, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(ssl_cert_loc))

            if ssl_cert_loc is None:
                response = requests.get(
                    url=url,
                    verify=verify_cert,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )
            else:
                response = requests.get(
                    url=url,
                    verify=ssl_cert_loc or True,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )

            logger.info("Token Validation Status:" + str(response.status_code))
            if 200 <= response.status_code < 300 and len(response.content) > 0:
                return True, response

            # in case of an unsuccessful request - log all of the request details
            logger.info("Demisto\'s token was not successfully validated")
            self.log_bad_request_details(response)

            raise Exception('Demisto token validation failed, please check that you have the correct token. Got status: ' + str(response.status_code) + ' with the following response: ' + json.dumps(response.json()))

        except requests.exceptions.SSLError as err:
            raise Exception('Token validation failed because of SSL validation error. In case you use self-signed '
                            'certificate refer to Demisto\'s manual. Got the following error: ' + str(err))

    def validate_permissions(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """Method is used to validate that the user have sufficient permissions in Demisto.

        It takes four arguments:
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
            logger.info("In validate permissions, passing verify=" + str(verify_cert) + " and ssl_cert_loc= " + str(
                ssl_cert_loc))

            if ssl_cert_loc is None:
                response = requests.get(
                    url=url,
                    verify=verify_cert,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )
            else:
                response = requests.get(
                    url=url,
                    verify=ssl_cert_loc or True,
                    allow_redirects=True,
                    headers=headers,
                    proxies=proxies
                )

            logger.info("Permissions Validation Status:" + str(response.status_code))
            if 200 <= response.status_code < 300 and len(response.content) > 0:
                return True, response

            # in case of an unsuccessful request - log all of the request details
            logger.info(
                "User don't have sufficient permissions in Demisto. Please check that you are working with the correct user and contact Demisto support."
            )
            self.log_bad_request_details(response)

            raise Exception("Permissions validation failed. User don't have sufficient permissions in Demisto. "
                            "Please check that you are working with the correct user and contact Demisto support."
                            "got status: " + str(response.status_code) + ' with the following response: ' + json.dumps(response.json()))

        except requests.exceptions.SSLError as err:
            raise Exception(
                'Permissions validation failed because of SSL validation error. In case you use self-signed '
                'certificate refer to Demisto\'s manual. Got the following error: ' + str(err))

    def validate_demisto_connection(self, url, authkey, verify_cert, ssl_cert_loc=None, proxies=None):
        """Method is used to validate all aspects of connection with Demisto.

        It takes four arguments:
        :param proxies: proxies
        :param url: Demisto URL, its mandatory parameter.
        :param authkey: authkey for authentication.
        :param verify_cert: If SSC is to be used
        :param ssl_cert_loc: Location of the public key of the SSC
        :return:
        """
        network_url = url + "/proxyMode"
        self.validate_network(
            network_url,
            verify_cert=verify_cert,
            ssl_cert_loc=ssl_cert_loc,
            proxies=proxies
        )

        token_url = url + "/incidenttype"
        self.validate_token(
            token_url,
            authkey,
            verify_cert=verify_cert,
            ssl_cert_loc=ssl_cert_loc,
            proxies=proxies
        )

        permissions_url = url + "/user"
        self.validate_permissions(
            permissions_url,
            authkey,
            verify_cert=verify_cert,
            ssl_cert_loc=ssl_cert_loc,
            proxies=proxies
        )

    def create_servers_config(self, urls, ports, passwords, certificates):
        """Method to call endpoint to retrieve servers."""
        configs_list = []

        if urls:
            splitted_urls = urls.split(',')
        else:
            splitted_urls = []

        if ports:
            splitted_ports = ports.split(',')
        else:
            splitted_ports = []

        if passwords:
            splitted_passwords = passwords.split(',')
        else:
            splitted_passwords = []

        if certificates:
            splitted_certificates = certificates.split(',')
        else:
            splitted_certificates = []

        if len(splitted_urls) != len(splitted_passwords):
            logger.exception("Each url should have a matching passwords. Current urls: " + str(
                splitted_urls) + " Current passwords: " + str(splitted_passwords))
            raise Exception("Each url should have a matching passwords. Current urls: " + str(
                splitted_urls) + " Current passwords: " + str(splitted_passwords))

        for url in splitted_urls:
            if not url or len(url) == 0 or (url and not re.match(IP_REGEX, url) and not re.match(DOMAIN_REGEX, url) and not re.match(URL_REGEX, url)):
                logger.exception(
                    "Invalid URL/IP/Domain, please check your server address. Address was " + str(url))
                raise Exception(
                    "Invalid URL/IP/Domain, please check your server address. Address was " + str(url))

            if not re.match(URL_REGEX, url):  # adding https prefix if needed
                server_url = 'https://' + url
            else:
                server_url = url
            configs_list.append({
                'url': url,
                'server_url': server_url
            })

        for idx, port in enumerate(splitted_ports):
            if port == '0' or port == 0:
                continue
            if port and not re.match(PORT_REGEX, port):
                logger.exception("Invalid Port Number. Port was " + str(port))
                raise Exception("Invalid Port Number. Port was " + str(port))
            else:
                configs_list[idx]['server_url'] += ":" + port
            configs_list[idx]['port'] = port

        for idx, password in enumerate(splitted_passwords):
            configs_list[idx]['password'] = password

        for idx, cert in enumerate(splitted_certificates):
            if cert == '0' or cert == 0:
                continue
            configs_list[idx]['cert'] = cert

        return configs_list

    def handleList(self, confInfo):
        """Method to list available config, if any."""
        config_dict = self.readConf("demistosetup")
        logger.debug("config dict is : " + json.dumps(config_dict))
        for stanza, settings in list(config_dict.items()):
            for key, val in list(settings.items()):
                confInfo[stanza].append(key, val)

    '''
    After user clicks Save on setup screen, take updated parameters,
    normalize them, and save them
    '''

    def handleEdit(self, confInfo):
        """Method to init the edit functions of the setup page."""
        proxies = self.get_proxy_settings()
        # logger.debug("caller args are: " + json.dumps(self.callerArgs.data))

        # checking if the user instructed not to use SSL - development environment scenario
        # getting the current configuration from Splunk
        validate_ssl = self.get_ssl_validation_settings()
        try:
            # servers_config is a list of [{server_url,port,password,base_url},{server_url,port,password,base_url}]
            servers_config = self.create_servers_config(
                self.callerArgs.data['DEMISTOURL'][0],
                self.callerArgs.data.get('PORT')[0],
                self.callerArgs.data['AUTHKEY'][0],
                self.callerArgs.data['SSL_CERT_LOC'][0]
            )
            '''
                Check connectivity with Demisto to verify that the configuration is correct.
                Store the configuration only if it was successful.
            '''
            server_cert_dict = {}
            for config in servers_config:
                if self.callerArgs.data['SSL_CERT_LOC']:
                    self.validate_demisto_connection(
                        config['server_url'],
                        config['password'],
                        verify_cert=validate_ssl,
                        ssl_cert_loc=config.get('cert'),
                        proxies=proxies
                    )
                    server_cert_dict[config['server_url']] = config.get('cert', '')
                else:
                    self.validate_demisto_connection(
                        config['server_url'],
                        config['password'],
                        verify_cert=validate_ssl,
                        proxies=proxies
                    )

                self.set_server_password(
                    new_password=config.get('password'),
                    server=config.get('server_url')
                )

                # BEYONDCORP - set BeyondCorp Key and Secret
                self.set_beyondcorp_passwords(
                    self.callerArgs.data['BEYOND_CORP_KEY'],
                    self.callerArgs.data['BEYOND_CORP_SECRET']
                )

            # Remove AUTHKEY from custom configuration.
            if self.callerArgs.data['PORT'][0] is None:
                self.callerArgs.data['PORT'] = ''

            if self.callerArgs.data['SSL_CERT_LOC'][0] is None:
                self.callerArgs.data['SSL_CERT_LOC'] = ''

            if self.callerArgs.data['EXCLUSION_LIST'][0] is None:
                self.callerArgs.data['EXCLUSION_LIST'] = ''

            if self.callerArgs.data['BEYOND_CORP_API'][0] is None:
                self.callerArgs.data['BEYOND_CORP_API'] = ''

            if self.callerArgs.data['BEYOND_CORP_KEY'][0] is None:
                self.callerArgs.data['BEYOND_CORP_KEY'] = ''

            if self.callerArgs.data['BEYOND_CORP_SECRET'][0] is None:
                self.callerArgs.data['BEYOND_CORP_SECRET'] = ''

            del self.callerArgs.data['AUTHKEY']
            del self.callerArgs.data['HTTPS_PROXY_PASSWORD']

            # BEYONDCORP
            # delete BeyondCorp key and secret from being store in cleartext in demistosetup.conf
            del self.callerArgs.data['BEYOND_CORP_KEY']
            del self.callerArgs.data['BEYOND_CORP_SECRET']

            self.callerArgs.data['SERVER_CERT'] = json.dumps(server_cert_dict)

            self.callerArgs.data['DEMISTOURL'] = ",".join([config.get('server_url') for config in servers_config])

            self.writeConf(
                'demistosetup',
                'demistoenv',
                self.callerArgs.data
            )

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
            splunk.rest.simpleRequest(
                '/services/messages',
                self.getSessionKey(),
                postargs=post_args
            )
            raise Exception("Error happened while setting up Demisto Add-on , error was: " + str(e))

    def handleReload(self, confInfo=None):
        """Handle refresh/reload of the configuration options."""
        pass


# initialize the handler
if __name__ == '__main__':
    admin.init(ConfigApp, admin.CONTEXT_APP_AND_USER)
