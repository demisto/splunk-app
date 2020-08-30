"""Demisto send alert class and methods."""
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
from demisto_incident import DemistoIncident

SPLUNK_PASSWORD_ENDPOINT = "/servicesNS/nobody/TA-Demisto/storage/passwords"
CONFIG_ENDPOINT = "/servicesNS/nobody/TA-Demisto/configs/conf-demistosetup/demistoenv/"

version = float(re.search(r"(\d+.\d+)", ver.__version__).group(1))

try:
    if version >= 6.4:
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

logger = DemistoConfig.get_logger("DEMISTOALERT")
modular_action_logger = ModularAction.setup_logger('demisto_modalert')


class DemistoAction(ModularAction):
    """Demisto action class used when invoking the splunk modular alert functions."""

    def create_demisto_incident(
        self,
        result,
        authkey,
        verify,
        search_query="",
        search_url="",
        ssl_cert_loc="",
        search_name=None,
        proxies=None,
        url=None,
        beyond_corp_key="",
        beyond_corp_secret="",
        beyond_corp_api=""
    ):
        """Function to package object matching what Demisto expects."""
        try:
            logger.info("create_demisto_incident called")
            demisto = DemistoIncident(logger)
            logger.info("Splunk search query is: " + search_query)
            logger.info("search_url is: %s", search_url)
            logger.info("Splunk search result is: " + json.dumps(result))

            resp = demisto.create_incident(
                authkey,
                self.configuration,
                verify,
                search_query,
                search_url,
                ssl_cert_loc,
                result,
                search_name,
                proxies,
                url=url,
                beyond_corp_key=beyond_corp_key,
                beyond_corp_secret=beyond_corp_secret,
                beyond_corp_api=beyond_corp_api
            )

            logger.info("Demisto response code is: " + str(resp.status_code))
            if resp.status_code == 201 or resp.status_code == 200:
                # Removing rawJSON from the response as it creates too large demistoResponse
                logger.debug("Demisto's response is: %s", resp.text)
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
                logger.error(
                    'Error in creating incident in Demisto, got status: ' +
                    str(resp.status_code) + ' with response: ' + json.dumps(resp.json())
                )

                logger.error("Demisto's response was: %s", resp.text)
                self.message(
                    'Error in creating incident in Demisto, got status: ' +
                    str(resp.status_code) + ' with response: ' + json.dumps(resp.json()),
                    status='failure')
                self.addevent(
                    resp.text +
                    "status= " +
                    str(resp.status_code),
                    sourcetype="demistoResponse"
                )

        except Exception as ex:
            logger.exception("Error in create_demisto_incident, error: %s", ex)
            self.message('Failed in creating incident in Demisto', status='failure')

            self.addevent(
                "Demisto Incident creation in create_demisto_incident function failed. " +
                "exception=" + str(ex), sourcetype="demistoResponse"
            )

    def get_password_for_server(self, save_name):
        """Function to read Splunk Demisto app endpoints for setup data."""
        try:
            r = splunk.rest.simpleRequest(
                SPLUNK_PASSWORD_ENDPOINT,
                self.session_key,
                method='GET',
                getargs={
                    'output_mode': 'json',
                    'search': save_name
                }
            )

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
            logger.exception("Error in create_demisto_incident, error: " + str(ex))

    def get_beyondcorp_passwords(self):
        """Retrieve Key and Secret."""
        beyond_corp_secret_clear = ""
        beyond_corp_key_clear = ""

        try:
            beyond_corp_key = splunk.rest.simpleRequest(
                SPLUNK_PASSWORD_ENDPOINT,
                self.session_key,
                method='GET',
                getargs={'output_mode': 'json', 'search': 'TA-Demisto-BeyondCorp-Key'}
            )

            beyond_corp_secret = splunk.rest.simpleRequest(
                SPLUNK_PASSWORD_ENDPOINT,
                self.session_key,
                method='GET',
                getargs={'output_mode': 'json', 'search': 'TA-Demisto-BeyondCorp-Secret'}
            )

            if 200 <= int(beyond_corp_key[0]["status"]) < 300:
                dict_data = json.loads(beyond_corp_key[1])
                if dict_data["entry"]:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto-BeyondCorp":
                            beyond_corp_key_clear = ele["content"]["clear_password"]
                            break

            if 200 <= int(beyond_corp_secret[0]["status"]) < 300:
                dict_data = json.loads(beyond_corp_secret[1])
                if dict_data["entry"]:
                    for ele in dict_data["entry"]:
                        if ele["content"]["realm"] == "TA-Demisto-BeyondCorp":
                            beyond_corp_secret_clear = ele["content"]["clear_password"]
                            break

            return beyond_corp_key_clear, beyond_corp_secret_clear

        except Exception as e:
            self.logger.exception(
                "Exception while retrieving BeyondCorp key or secret. " +
                "The error was: " + str(e)
            )
            raise Exception(
                "Exception while retrieving BeyondCorp key or secret. error is: " +
                str(e)
            )

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
            raise Exception("The Alert name must not have pipe (|) char in its name - it causes Splunk to send incomplete data")

        get_args = {
            'output_mode': 'json',
        }
        r = splunk.rest.simpleRequest(
            search_uri,
            sessionKey=modaction.session_key,
            getargs=get_args,
            method='GET'
        )
        result_op = json.loads(r[1])
        if len(result_op["entry"]) > 0:
            search = result_op["entry"][0]["content"]["qualifiedSearch"]

        input_args = cli.getConfStanza('demistosetup', 'demistoenv')

        # getting the current configuration from Splunk
        success, content = splunk.rest.simpleRequest(
            CONFIG_ENDPOINT,
            modaction.session_key,
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
        r = splunk.rest.simpleRequest(
            SPLUNK_PASSWORD_ENDPOINT,
            modaction.session_key,
            method='GET',
            getargs={
                'output_mode': 'json',
                'search': 'TA-Demisto-Proxy'
            }
        )

        proxy = None

        if 200 <= int(r[0]["status"]) < 300:
            dict_data = json.loads(r[1])
            if len(dict_data["entry"]) > 0:
                for ele in dict_data["entry"]:
                    if ele["content"]["realm"] == "TA-Demisto-Proxy":
                        proxy = ele["content"]["clear_password"]
                        break

        proxies = {} if proxy is None else json.loads(proxy)

        # BEYONDCORP
        beyond_corp_key, beyond_corp_secret = modaction.get_beyondcorp_passwords()
        beyond_corp_api = config.get('BEYOND_CORP_API', '')

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
                save_name = hashlib.sha1(url.strip()).hexdigest()
                password = modaction.get_password_for_server(save_name)
                # Process the result set by opening results_file with gzip
                with gzip.open(modaction.results_file, 'rb') as fh:
                    # Iterate the result set using a dictionary reader
                    # We also use enumerate which provides "num" which
                    # can be used as the result ID (rid)
                    for num, result in enumerate(csv.DictReader(fh)):
                        result.setdefault('rid', str(num))
                        modaction.update(result)
                        modaction.invoke()
                        modaction.create_demisto_incident(
                            result,
                            url=url,
                            authkey=password,
                            verify=validate_ssl,
                            search_query=search,
                            search_url=search_url,
                            ssl_cert_loc=server_certs.get(url, ''),
                            search_name=search_name,
                            proxies=proxies,
                            beyond_corp_key=beyond_corp_key,
                            beyond_corp_secret=beyond_corp_secret,
                            beyond_corp_api=beyond_corp_api
                        )
        else:
            url = modaction.configuration.get('demisto_server', '')
            save_name = hashlib.sha1(url).hexdigest()
            password = modaction.get_password_for_server(save_name)

            # Process the result set by opening results_file with gzip
            with gzip.open(modaction.results_file, 'rb') as fh:
                # Iterate the result set using a dictionary reader
                # We also use enumerate which provides "num" which
                # can be used as the result ID (rid)
                for num, result in enumerate(csv.DictReader(fh)):
                    result.setdefault('rid', str(num))
                    modaction.update(result)
                    modaction.invoke()
                    modaction.create_demisto_incident(
                        result,
                        url=url,
                        authkey=password,
                        verify=validate_ssl,
                        search_query=search,
                        search_url=search_url,
                        ssl_cert_loc=server_certs.get(url, ''),
                        search_name=search_name,
                        proxies=proxies,
                        beyond_corp_key=beyond_corp_key,
                        beyond_corp_secret=beyond_corp_secret,
                        beyond_corp_api=beyond_corp_api
                    )

        modaction.writeevents(index="main", source='demisto')

    except Exception as e:
        # adding additional logging since adhoc search invocations do not write to stderr
        logger.exception("Error in main, error: " + str(e))
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception as ex:
            modular_action_logger.critical(ex)
        sys.exit(-1)
