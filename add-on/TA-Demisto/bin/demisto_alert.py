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

import splunk.rest
from splunk.clilib import cli_common as cli
import splunk.version as ver

from demisto_config import DemistoConfig
from demisto_incident import DemistoIncident

# PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/admin/passwords?output_mode=json"
SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
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

    def create_demisto_incident(self, result, url, authkey, verify, search_query="", search_url="", ssl_cert_loc="",
                                search_name=None, proxies=None):
        try:
            logger.info("create_demisto_incident called")
            demisto = DemistoIncident(logger)
            resp = demisto.create_incident(url, authkey, self.configuration, verify, search_query, search_url,
                                           ssl_cert_loc, result, search_name, proxies)
            logger.info("Demisto's response is: " + json.dumps(resp.json()))

            if resp.status_code == 201 or resp.status_code == 200:
                # self.message logs the string to demisto_modalert.log
                self.message('Successfully created incident in Demisto', status='success')

                # Removing rawJSON from the response as it creates too large demistoResponse
                resp = json.loads(resp.text)
                del resp["rawJSON"]
                resp = json.dumps(resp)

                # self.addevent sends the following message to splunk and adds it as event there
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


if __name__ == '__main__':

    modaction = None
    try:
        logger.info("In Main Method")
        modaction = DemistoAction(sys.stdin.read(), modular_action_logger, 'demisto')

        search = ""
        search_name = modaction.settings.get('search_name', '')
        search_url = modaction.settings.get('results_link', '')
        search_uri = modaction.settings.get('search_uri', '')

        if not (not search_name):
            logger.info("Creating search uri")
            search_app_name = modaction.settings.get('app', '')
            search_uri = urllib.pathname2url("/services/saved/searches/" + search_name)

        if not (not search_uri):
            r = splunk.rest.simpleRequest(search_uri + "?output_mode=json", modaction.session_key, method='GET')
            result_op = json.loads(r[1])
            search = ""
            if len(result_op["entry"]) > 0:
                search = result_op["entry"][0]["content"]["qualifiedSearch"]

        input_args = cli.getConfStanza('demistosetup', 'demistoenv')

        if not input_args["DEMISTOURL"]:
            modaction.message('Failed in creating incident in Demisto',
                              status='failure')

            modaction.addevent(
                "Demisto URL must be set, please complete Demisto setup status=2",
                sourcetype="demistoResponse")

            logger.exception("Demisto URL must be set, please complete Demisto setup")
            modaction.writeevents(index="main", source='demisto')
            sys.exit(-1)

        else:
            url = "https://" + input_args["DEMISTOURL"]

        if "PORT" in input_args:
            url += ":" + str(input_args["PORT"])

        if modaction.session_key is None:
            logger.exception("Can not execute this script outside Splunk")
            sys.exit(-1)

        # todo remove logging below
        logger.info("--------- input args-------")
        logger.info(json.dumps(input_args))
        logger.info("--------- input args-------")

        proxies = {}
        http_proxy = input_args.get('HTTP_PROXY', None)
        https_proxy = input_args.get('HTTPS_PROXY', None)

        if http_proxy is not None:
            proxies['http'] = http_proxy

        if https_proxy is not None:
            proxies['https'] = https_proxy

        validate_ssl = input_args.get("validate_ssl", True)
        # logger.info("validate ssl is : " + validate_ssl)

        if validate_ssl == 0 or validate_ssl == "0":
            validate_ssl = False

        r = splunk.rest.simpleRequest(SPLUNK_PASSWORD_ENDPOINT, modaction.session_key, method='GET', getargs={
            'output_mode': 'json'})
        logger.info("Demisto alert: response from app password end point:" + str(r[1]))
        # logger.info("response from app password end point in get_app_password is :" + str(r))
        if 200 <= int(r[0]["status"]) < 300:
            dict_data = json.loads(r[1])
            password = ""
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:
                    if ele["content"]["realm"] == "TA-Demisto":
                        password = ele["content"]["clear_password"]
                        userName = ele["content"]["username"]
                        break

        else:
            raise Exception(
                "Authentication key couldn't be retrieved from storage/passwords, the response was: " + str(r))

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
                                                  search_query=search,
                                                  search_url=search_url,
                                                  ssl_cert_loc=input_args.get("SSL_CERT_LOC", ''),
                                                  search_name=search_name, proxies=proxies)
                time.sleep(1.6)

        modaction.writeevents(index="main", source='demisto')

    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        logger.exception("Error in main, error: " + str(e))
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception as ex:
            modular_action_logger.critical(ex)
        sys.exit(-1)
