# !/usr/bin/env python
from __future__ import absolute_import

import json
import logging
import sys
import csv
import gzip
import re
import six.moves.urllib.request
import six.moves.urllib.parse
import six.moves.urllib.error
import hashlib

import splunk.rest
from splunk.clilib import cli_common as cli
import splunk.version as ver

from demisto_config import DemistoConfig
from demisto_indicator import DemistoIndicator

SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"

VERSION = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

# Importing the cim_actions.py library
# A.  Import make_splunkhome_path
# B.  Append library path to sys.path
# C.  Import ModularAction from cim_actions

try:
    if VERSION >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError:
    raise ImportError("Import splunk sub libraries failed\n")

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Demisto", "bin", "lib"]))

try:
    from cim_actions import ModularAction
except Exception:
    sys.exit(3)

logger = DemistoConfig.get_logger("DEMISTOINDICATOR")
modular_action_logger = ModularAction.setup_logger('demisto_modalert')


class DemistoAction(ModularAction):

    def create_demisto_indicator(
            self,
            result,
            authkey,
            verify,
            indicator,
            indicator_type,
            reputation,
            comment,
            ssl_cert_loc="",
            search_name=None,
            proxies=None,
            url=None):
        """Function to package object matching what Demisto expects."""
        try:
            logger.info("create_demisto_indicator called")
            demisto = DemistoIndicator(logger)
            logger.info("indicator is: %s", indicator)
            logger.info("indicator type is: %s", indicator_type)
            logger.info("reputation is: %s", reputation)

            resp = demisto.create_indicator(
                authkey,
                indicator,
                indicator_type,
                reputation,
                comment,
                verify,
                ssl_cert_loc,
                proxies,
                url=url)

            logger.info("Demisto response code is: %s", resp.status_code)
            if resp.status_code == 201 or resp.status_code == 200:
                if resp.json() is None:
                    self.message('Indicator not created. NULL value was returned.  Please check that this indicator is not whitelisted', status='failure')
                    logger.info("In create_indicator.  NULL value was returned.  Please check that this indicator is not whitelisted")
                else:
                    logger.debug("Demisto's response is: %s", resp.text)
                    # self.message logs the string to demisto_modalert.log
                    self.message('Successfully created indicator in Demisto', status='success')
                    logger.info("Successfully created indicator in Demisto")

                resp = json.loads(resp.text)
                resp = json.dumps(resp)

                # self.addevent sends the following message to Splunk and adds it as event there
                self.addevent(resp, sourcetype="demistoResponse")
            else:
                logger.error(
                    'Error in creating indicator in Demisto, got status: ' + str(resp.status_code) + ' with response: ' + json.dumps(resp.json())
                )

                logger.error("Demisto's response was: %s", resp.text)
                self.message(
                    'Error in creating indicator in Demisto, got status: ' + str(resp.status_code) + ' with response: ' + json.dumps(resp.json()), status='failure')
                self.addevent(resp.text + "status= " + str(resp.status_code), sourcetype="demistoResponse")
        except Exception as ex:
            logger.exception("Error in create_demisto_indicator, error: %s", ex)
            self.message('Failed in creating indicator in Demisto', status='failure')

            self.addevent(
                "Demisto Indicator creation in create_demisto_indicator function failed. Exception=" + str(ex), sourcetype="demistoResponse"
            )

    def get_password_for_server(self, save_name):
        try:
            r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT, self.session_key, method='GET', getargs={
                'output_mode': 'json', 'search': save_name})

            password = ""

            if 200 <= int(r[0]["status"]) < 300:
                dict_data = json.loads(r[1])
                if len(dict_data["entry"]) > 0:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto" and ele["name"] == "TA-Demisto:{}:".format(
                                save_name):
                            password = ele["content"].get('clear_password')
                            break

            if not password:
                raise Exception(
                    "Authentication key couldn't be retrieved from storage/passwords for server with hash {},"
                    " the response was: ".format(save_name) + str(r))
            return password
        except Exception as ex:
            logger.exception("Error in create_demisto_indicator, error: " + str(ex))


if __name__ == '__main__':

    modaction = None
    try:
        logger.info("In Main Method")
        modaction = DemistoAction(sys.stdin.read(), modular_action_logger, 'demisto')

        search = ""
        search_name = modaction.settings.get('search_name', '')
        search_url = modaction.settings.get('results_link', '')
        search_uri = modaction.settings.get('search_uri', '')

        logger.info("Alert name is " + search_name)
        logger.info("Search uri is " + search_uri)
        logger.info("Manually created Search uri is " + "/services/saved/searches/" + six.moves.urllib.parse.quote(search_name))

        if not search_name:
            logger.info("Creating search uri")
            search_app_name = modaction.settings.get('app', '')
            search_uri = six.moves.urllib.request.pathname2url("/services/saved/searches/" + six.moves.urllib.parse.quote(search_name))
        # pipe in the alert name breaks Splunk's ability to send us the alert data correctly
        elif '|' in search_name:
            raise Exception(
                "The Alert name must not have pipe (|) char in its name - it causes Splunk to send incomplete data")

        get_args = {
            'output_mode': 'json',
        }
        r = splunk.rest.simpleRequest(search_uri, sessionKey=modaction.session_key, getargs=get_args, method='GET')
        result_op = json.loads(r[1])
        if len(result_op["entry"]) > 0:
            search = result_op["entry"][0]["content"]["qualifiedSearch"]

        input_args = cli.getConfStanza('demistosetup', 'demistoenv')

        # getting the current configuration from Splunk
        success, content = splunk.rest.simpleRequest(CONFIG_ENDPOINT, modaction.session_key, method='GET',
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

        demisto_servers = config.get('DEMISTOURL', '').strip().split(',')
        try:
            server_certs = json.loads(config.get('SERVER_CERT', ''))
        except Exception:
            server_certs = {
                demisto_servers[0]: ''
            }
        server_certs = json.loads(config.get('SERVER_CERT', ''))
        validate_ssl = config.get('VALIDATE_SSL', True)

        if validate_ssl == 0 or validate_ssl == "0":
            validate_ssl = False
        else:
            validate_ssl = True

        if modaction.session_key is None:
            logger.exception("Can not execute this script outside Splunk")
            sys.exit(-1)

        # getting https proxy from Splunk - it might not exist
        r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT, modaction.session_key, method='GET', getargs={
            'output_mode': 'json', 'search': 'TA-Demisto-Proxy'})
        proxy = None
        if 200 <= int(r[0]["status"]) < 300:
            dict_data = json.loads(r[1])
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:
                    if ele["content"]["realm"] == "TA-Demisto-Proxy":
                        proxy = ele["content"]["clear_password"]
                        break

        proxies = {} if proxy is None else json.loads(proxy)
        if modaction.configuration.get('send_all_servers', '') == '1':

            # check exclusion list
            logger.debug("Checking exclusion list for sending to all servers")
            exclusion_list = config.get('EXCLUSION_LIST', '').strip().split(',')
            for item in exclusion_list:
                item = item.strip()
                if item in demisto_servers:
                    demisto_servers.remove(item)
                    logger.debug("Excluding server from incident creation: " + str(item))

            for url in demisto_servers:
                # getting Demisto's API key from Splunk
                save_name = hashlib.sha1(url).hexdigest()
                password = modaction.get_password_for_server(save_name)
                '''
                Process the result set by opening results_file with gzip
                '''
                with gzip.open(modaction.results_file, 'rb') as fh:
                    '''
                    ## Iterate the result set using a dictionary reader
                    ## We also use enumerate which provides "num" which
                    ## can be used as the result ID (rid)
                    '''
                    for num, result in enumerate(csv.DictReader(fh)):
                        result.setdefault('rid', str(num))
                        modaction.update(result)
                        modaction.invoke()
                        modaction.create_demisto_indicator(
                            result,
                            url=url,
                            authkey=password,
                            verify=validate_ssl,
                            indicator=modaction.configuration.get('indicator'),
                            indicator_type=modaction.configuration.get('indicator_type'),
                            reputation=modaction.configuration.get('reputation'),
                            comment=modaction.configuration.get('comment'),
                            ssl_cert_loc=server_certs.get(url, ''),
                            search_name=search_name,
                            proxies=proxies)
        else:
            url = modaction.configuration.get('demisto_server', '')
            save_name = hashlib.sha1(url).hexdigest()
            password = modaction.get_password_for_server(save_name)

            '''
            Process the result set by opening results_file with gzip
            '''
            with gzip.open(modaction.results_file, 'rb') as fh:
                '''
                ## Iterate the result set using a dictionary reader
                ## We also use enumerate which provides "num" which
                ## can be used as the result ID (rid)
                '''
                for num, result in enumerate(csv.DictReader(fh)):
                    result.setdefault('rid', str(num))
                    modaction.update(result)
                    modaction.invoke()
                    modaction.create_demisto_indicator(
                        result,
                        url=url,
                        authkey=password,
                        verify=validate_ssl,
                        indicator=modaction.configuration.get('indicator'),
                        indicator_type=modaction.configuration.get('indicator_type'),
                        reputation=modaction.configuration.get('reputation'),
                        comment=modaction.configuration.get('comment'),
                        ssl_cert_loc=server_certs.get(url, ''),
                        search_name=search_name,
                        proxies=proxies)

        modaction.writeevents(index="main", source='demisto')

    except Exception as e:
        # adding additional logging since adhoc search invocations do not write to stderr
        logger.exception("Error in main, error: " + str(e))
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception as ex:
            modular_action_logger.critical(ex)
        sys.exit(-1)
