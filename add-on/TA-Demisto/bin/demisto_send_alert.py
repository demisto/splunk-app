#!/usr/bin/env python

#
# This code was written by Demisto Inc.
#

import json
import logging
import sys
import time
import csv
import gzip
import re
import urllib
import hashlib

import splunk.rest
from splunk.clilib import cli_common as cli
import splunk.version as ver

from demisto_config import DemistoConfig
from demisto_incident import DemistoIncident

SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"

version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

# Importing the cim_actions.py library
# A.  Import make_splunkhome_path
# B.  Append library path to sys.path
# C.  Import ModularAction from cim_actions

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    raise ImportError("Import splunk sub libraries failed\n")

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Demisto", "bin", "lib"]))

try:
    from cim_actions import ModularAction
except:
    sys.exit(3)

logger = DemistoConfig.get_logger("DEMISTOALERT")
modular_action_logger = ModularAction.setup_logger('demisto_modalert')


class DemistoAction(ModularAction):

    def create_demisto_incident(self, result, authkey, verify, search_query="", search_url="",
                                ssl_cert_loc="", search_name=None, proxies=None, url=None):
        try:
            logger.info("create_demisto_incident called")
            demisto = DemistoIncident(logger)

            resp = demisto.create_incident(authkey, self.configuration, verify, search_query, search_url,
                                           ssl_cert_loc, result, search_name, proxies, url=url)
            logger.debug("Demisto's response is: " + json.dumps(resp.json()))
            logger.info("Demisto response code is " + str(resp.status_code))
            if resp.status_code == 201 or resp.status_code == 200:
                # self.message logs the string to demisto_modalert.log
                self.message('Successfully created incident in Demisto', status='success')
                logger.info("Successfully created incident in Demisto")

                # Removing rawJSON from the response as it creates too large demistoResponse
                resp = json.loads(resp.text)
                del resp["rawJSON"]
                resp = json.dumps(resp)

                # self.addevent sends the following message to Splunk and adds it as event there
                self.addevent(resp, sourcetype="demistoResponse")
            else:
                logger.error('Error in creating incident in Demisto, got status: ' + str(resp.status_code)
                             + ' with response: ' + json.dumps(resp.json()))

                self.message(
                    'Error in creating incident in Demisto, got status: ' + str(resp.status_code)
                    + ' with response: ' + json.dumps(resp.json()),
                    status='failure')

                self.addevent(
                    resp.text + "status= " + str(resp.status_code),
                    sourcetype="demistoResponse")

        except Exception as ex:
            logger.exception("Error in create_demisto_incident, error: " + str(ex))
            self.message('Failed in creating incident in Demisto',
                         status='failure')

            self.addevent(
                "Demisto Incident creation in create_demisto_incident function failed. exception=" + str(ex),
                sourcetype="demistoResponse")

    def get_password_for_server(self, save_name):
        r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT, self.session_key, method='GET', getargs={
            'output_mode': 'json', 'search': save_name})

        password = ""

        if 200 <= int(r[0]["status"]) < 300:
            dict_data = json.loads(r[1])
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:
                    if ele["content"]["realm"] == "TA-Demisto" and ele["name"] == "TA-Demisto:{}:".format(save_name):
                        password = ele["content"].get('clear_password')
                        break

        if not password:
            raise Exception(
                "Authentication key couldn't be retrieved from storage/passwords for server {}, the response was: ".format(
                    modaction.configuration.get('demisto_server', '')) + str(r))
        return password

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
        logger.info("Manually created Search uri is " + "/services/saved/searches/" + urllib.quote(search_name))

        if not search_name:
            logger.info("Creating search uri")
            search_app_name = modaction.settings.get('app', '')
            search_uri = urllib.pathname2url("/services/saved/searches/" + urllib.quote(search_name))

        if not search_uri:
            get_args = {
                'output_mode': 'json',
            }
            r = splunk.rest.simpleRequest(search_uri, sessionKey=modaction.session_key, getargs=get_args, method='GET')
            result_op = json.loads(r[1])
            search = ""
            if len(result_op["entry"]) > 0:
                search = result_op["entry"][0]["content"]["qualifiedSearch"]

        input_args = cli.getConfStanza('demistosetup', 'demistoenv')

        # getting the current configuration from Splunk
        get_args = {
            'output_mode': 'json',
        }
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

        demisto_servers = config.get('DEMISTOURL', '').split(',')

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
        if modaction.configuration.get('send_all_servers', ''):
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
                        modaction.create_demisto_incident(result, url=url, authkey=password, verify=validate_ssl,
                                                          search_query=search, search_url=search_url,
                                                          ssl_cert_loc=input_args.get("SSL_CERT_LOC", ''),
                                                          search_name=search_name, proxies=proxies)
        else:
            save_name = hashlib.sha1(modaction.configuration.get('demisto_server', '')).hexdigest()
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
                    modaction.create_demisto_incident(result, url=url, authkey=password, verify=validate_ssl,
                                                      search_query=search, search_url=search_url,
                                                      ssl_cert_loc=input_args.get("SSL_CERT_LOC", ''),
                                                      search_name=search_name, proxies=proxies)

        modaction.writeevents(index="main", source='demisto')

    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        logger.exception("Error in main, error: " + str(e))
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception as ex:
            modular_action_logger.critical(ex)
        sys.exit(-1)
