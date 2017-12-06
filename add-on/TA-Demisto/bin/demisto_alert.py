#!/usr/bin/env python

#
# This code is written by Demisto Inc.


import json
import os
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
import csv
import gzip
import re
import urllib

import splunk.rest
import requests
from requests import Request
from splunk.clilib import cli_common as cli
import splunk.version as ver
import datetime


version = float(re.search("(\d+.\d+)", ver.__version__).group(1))


# Importing the cim_actions.py library
# A.  Import make_splunkhome_path
# B.  Append your library path to sys.path
# C.  Import ModularAction from cim_actions

maxbytes = 20000

try:
    if version >= 6.4:
        from splunk.clilib.bundle_paths import make_splunkhome_path
    else:
        from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
except ImportError as e:
    sys.exit(3)

sys.path.append(make_splunkhome_path(["etc", "apps", "TA-Demisto", "bin", "lib"]))


def get_logger(logger_id):
    log_path = make_splunkhome_path(["var", "log", "demisto"])
    if not (os.path.isdir(log_path)):
        os.makedirs(log_path)

    handler = RotatingFileHandler(log_path + '/demisto.log', maxBytes = maxbytes,
                                  backupCount = 20)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger = logging.getLogger(logger_id)
    logger.setLevel(logging.INFO)

    logger.addHandler(handler)
    return logger


from cim_actions import ModularAction

logger = get_logger("DEMISTOALERT")
logger1 = ModularAction.setup_logger('demisto_modalert')


class DemistoAction(ModularAction):
    def dowork(self, result, url, authkey, verify, search_query = "", search_url = "", ssl_cert_loc = ""):

        try:
            logger.info("Do Work called")

            resp = createIncident(url, authkey, self.configuration, verify, search_query, search_url, ssl_cert_loc, result)

            if resp.status_code == 201 or resp.status_code == 200:
                self.message('Successfully created incident in Demisto', status = 'success')
                self.addevent(
                    resp.text,
                    sourcetype = "demistoResponse")
            else:
                self.message('Error in creating incident in Demisto ', status = 'failure')
                self.addevent(
                    resp.text + "status= " + str(resp.status_code),
                    sourcetype = "demistoResponse")

        except Exception as e:
            logger.exception("Error in DO work")
            self.message('Failed in creating incident in Demisto',
                         status = 'failure')

            self.addevent(
                "Demisto Incident creation failed exception=" + str(e) + " status=2",
                sourcetype = "demistoResponse")


'''
    This method is used to create incident into Demisto. It takes four arguments and all are required:
    @url: Demisto URL, its mandatory parameter.
    @authkey: Requires parameter, used for authentication.
    @data: Incident information,
    @verify: Indicates if self signed certificates are allowed or not.
'''


def createIncident(url, authkey, data, verify_req, search_query = "", search_url = "", ssl_cert_loc = "", result=None):
    incident = {}
    incident["details"] = data.get('details', '')

    local_offset = datetime.timedelta(seconds=-time.altzone)
    matchObj = re.match("(.*):(\d+):(\d+)", str(local_offset))
    hours = int(matchObj.group(1))
    timezone = "-"+"{:0>2}".format(int(matchObj.group(1))*-1) +":"+matchObj.group(2) \
        if hours <0 else "+"+"{:0>2}".format(int(matchObj.group(1))) +":"+matchObj.group(2)

    incident["occurred"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(int(float(data["occured"])))) + timezone

    # Always pass True for create investigation
    incident["createInvestigation"] = True

    incident["name"] = data.get('incident_name', '')

    incident["type"] = data.get('type', '')

    ignore_labels=data.get('ignore_labels','').lower().split(",")

    if "severity" in data:
        incident["severity"] = float(data["severity"])

    label = []
    data_dir = {'type': 'SplunkSearch', 'value': search_query}
    label.append(data_dir)

    data_dir = {'type': 'SplunkURL', 'value': search_url}
    label.append(data_dir)

    logger.debug("Label::::"+str(result.keys()))

    logger.debug("Ignore Label::::"+str(ignore_labels))


    if data.get("labels"):
        strdata = data["labels"].split(",")
        for data_label in strdata:
            paramData = data_label.split(":")
            data_dir = {"type": paramData[0], "value": ":".join(paramData[1:])}
            label.append(data_dir)
    else:
        for key in result.keys():
            if key.lower() not in ignore_labels and not key.startswith("__"):
                data_dir = {"type": key, "value": result[key]}
                label.append(data_dir)

    incident["labels"] = label


    if "custom_field" in data:
        strdata = data["custom_field"].split(",")
        custom_fields = {}
        for data in strdata:
            paramData = data.split(":")
            custom_fields[paramData[0]] = ":".join(paramData[1:])

        incident["customFields"] = custom_fields

    s = requests.session()

    logger.debug("JSON data for the Incident=" + json.dumps(incident))
    req = Request('POST', url + "/incident/splunkapp", data = json.dumps(incident))
    prepped = s.prepare_request(req)

    prepped.headers['Authorization'] = authkey
    prepped.headers['Content-type'] = "application/json"
    prepped.headers['Accept'] = "application/json"


    if ssl_cert_loc:
        logger.info("Passing verify=" +ssl_cert_loc )
        resp = s.send(prepped, verify = ssl_cert_loc)
    else:
        logger.info("Passing verify=True")
        resp = s.send(prepped, verify = True)


    return resp


'''
    This method is used to validate Authorisation token. It takes four arguments.:
    @url: Demisto URL, its mandatory parameter.
    @authkey: Requires parameter, used for authentication.
    @verify_req: If SSC is to be used,
    @ssl_cert_loc: Location of the public key of the SSC.
'''


def validate_token(url, authkey, verify_cert, ssl_cert_loc = ""):
    headers = {'Authorization': authkey, 'Content-type': 'application/json', 'Accept': 'application/json'}

    if verify_cert and ssl_cert_loc is None:
        logger.info("Passing"+str(verify_cert))
        r = requests.get(url = url, verify = True,
                         allow_redirects = True, headers = headers)
    else:
        logger.info("Passing verify="+ssl_cert_loc)
        r = requests.get(url = url, verify = ssl_cert_loc or True,
                         allow_redirects = True, headers = headers)

    logger.info("Token Validation Status:" + str(r.status_code))
    if 200 <= r.status_code < 300 and len(r.content) > 0:
        return True

    return False


if __name__ == '__main__':

    modaction = None
    try:
        logger.info("In Main Method")
        modaction = DemistoAction(sys.stdin.read(), logger1, 'demisto')

        search = ""

        search_name = modaction.settings.get('search_name', '')

        search_url = modaction.settings.get('results_link', '')

        search_uri = modaction.settings.get('search_uri', '')

        if not (not search_name):
            logger.info("For Splunk <6.4, creating search uri")
            search_app_name = modaction.settings.get('app', '')
            search_uri = urllib.pathname2url("/services/saved/searches/" + search_name)

        if not (not search_uri):
            r = splunk.rest.simpleRequest(search_uri + "?output_mode=json", modaction.session_key, method = 'GET')
            result_op = json.loads(r[1])
            search = ""
            if len(result_op["entry"]) > 0:
                search = result_op["entry"][0]["content"]["qualifiedSearch"]

        inputargs = cli.getConfStanza('demistosetup', 'demistoenv')

        if not inputargs["DEMISTOURL"]:
            modaction.message('Failed in creating incident in Demisto',
                              status = 'failure')

            modaction.addevent(
                "Demisto URL must be set, please complete Demisto setup status=2",
                sourcetype = "demistoResponse")

            logger.exception("Demisto URL must be set, please complete Demisto setup")
            modaction.writeevents(index = "main", source = 'demisto')
            sys.exit(3)

        else:
            url = "https://" + inputargs["DEMISTOURL"]

        if "PORT" in inputargs:
            url += ":" + str(inputargs["PORT"])

        if modaction.session_key is None:
            logger.exception("Can not execute this script outside Splunk")
            sys.exit(3)

        r = splunk.rest.simpleRequest("/servicesNS/nobody/TA-Demisto/admin/passwords?output_mode=json",
                                      modaction.session_key, method = 'GET')
        if 200 <= int(r[0]["status"]) <= 300:
            result_op = json.loads(r[1])
            password = ""
            if len(result_op["entry"]) > 0:
                for ele in result_op["entry"]:

                    if ele["content"]["realm"] == "TA-Demisto":
                        password = ele["content"]["clear_password"]
                        userName = ele["content"]["username"]
                        break
        else:
            raise Exception("Auth key couldn't be retrived from storage/passwords")

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
                modaction.dowork(result, url = url, authkey = password, verify = True,
                                 search_query = search,
                                 search_url = search_url, ssl_cert_loc = inputargs.get("SSL_CERT_LOC",''))
                time.sleep(1.6)

        modaction.writeevents(index = "main", source = 'demisto')
    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        logger.exception("Error in main")
        try:
            modaction.message(e, status = 'failure', level = logging.CRITICAL)
        except:
            logger1.critical(e)
        logger.exception("ERROR Unexpected error")
        sys.exit(3)


