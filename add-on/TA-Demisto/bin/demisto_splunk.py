#!/usr/bin/env python

#
# This code is written by Demisto Inc.


import json
import time
import re
import urllib

import splunk.rest
import requests
from requests import Request


class DemistoIncident():
    def __init__(self, logger):
        """

        :rtype: object
        """
        self.logger = logger

    '''
        This method is used to create incident into Demisto. It takes four arguments and all are mandatory:
        @url: Demisto URL, its mandatory parameter.
        @authkey: Requires parameter, used for authentication.
        @data: Incident information,
        @verify: Indicates if self signed certificates are allowed or not.
    '''
    def create_incident(self, url, authkey, data, verify_req, search_query="", search_url="", ssl_cert_loc="",
                        result=None,
                        search_name=None):
        # todo move dictionary creation into a different function
        incident = {}

        incident["details"] = data.get('details', '')

        # todo simplify this
        zone = time.strftime("%z")
        timezone = zone[-5:][:3] + ":" + zone[-5:][3:]

        incident["occurred"] = time.strftime("%Y-%m-%dT%H:%M:%S",
                                             time.localtime(int(float(data["occured"])))) + timezone

        # Always pass True for create investigation
        incident["createInvestigation"] = True

        incident["name"] = data.get('incident_name', '')

        incident["type"] = data.get('type', '')

        ignore_labels = data.get('ignore_labels', '').lower().split(",")

        if "severity" in data:
            incident["severity"] = float(data["severity"])

        labels = []
        data_dir = {'type': 'SplunkSearch', 'value': search_query}
        labels.append(data_dir)

        data_dir = {'type': 'SplunkURL', 'value': search_url}
        labels.append(data_dir)

        if search_name:
            data_dir = {'type': 'search_name', 'value': search_name}
            labels.append(data_dir)

        self.logger.debug("Label::::" + str(result.keys()))
        self.logger.debug("Ignore Label::::" + str(ignore_labels))

        # todo change to if 'labels' in data
        if data.get("labels"):
            strdata = data["labels"].split(",")
            for data_label in strdata:
                param_data = data_label.split(":")
                data_dir = {"type": param_data[0], "value": ":".join(param_data[1:])}
                labels.append(data_dir)
        else:
            for key in result.keys():
                if key.lower() not in ignore_labels and not key.startswith("__"):
                    data_dir = {"type": key, "value": result[key]}
                    labels.append(data_dir)

        incident["labels"] = labels

        if "custom_field" in data:
            strdata = data["custom_field"].split(",")
            custom_fields = {}
            for data in strdata:
                param_data = data.split(":")
                custom_fields[param_data[0]] = ":".join(param_data[1:])

            incident["customFields"] = custom_fields

        incident["rawJSON"] = json.dumps(result)

        s = requests.session()

        self.logger.debug("JSON data for the Incident=" + json.dumps(incident))
        # todo consider moving the api path to global var
        req = Request('POST', url + "/incident/splunkapp", data=json.dumps(incident))
        prepped = s.prepare_request(req)

        prepped.headers['Authorization'] = authkey
        prepped.headers['Content-type'] = "application/json"
        prepped.headers['Accept'] = "application/json"

        # todo change the mechanism for ssl verification with the global splunk vars
        if ssl_cert_loc:
            self.logger.info("Setting passed certificate location as verify=" + ssl_cert_loc)
            resp = s.send(prepped, verify=ssl_cert_loc)
        else:
            # logger.info("Using default value for verify = False")
            # resp = s.send(prepped, verify = False)

            self.logger.info("Using default value for verify = True")
            resp = s.send(prepped, verify=True)

        return resp

    '''
        This method is used to validate Authorization token. It takes four arguments:
        @url: Demisto URL, its mandatory parameter.
        @authkey: Requires parameter, used for authentication.
        @verify_req: If SSC is to be used,
        @ssl_cert_loc: Location of the public key of the SSC.
    '''

    def validate_token(self, url, authkey, verify_cert, ssl_cert_loc=None):
        headers = {'Authorization': authkey, 'Content-type': 'application/json', 'Accept': 'application/json'}

        if verify_cert and ssl_cert_loc is None:
            # logger.info("Passing verify = False")
            # r = requests.get(url = url, verify = False,allow_redirects = True, headers = headers)
            # todo change the ssl verification mechanism
            self.logger.info("Using default value for verify = True")
            r = requests.get(url=url, verify=True, allow_redirects=True, headers=headers)
        else:
            self.logger.info("Passing verify=" + str(ssl_cert_loc))
            r = requests.get(url=url, verify=ssl_cert_loc or True,
                             allow_redirects=True, headers=headers)
        # todo change the log to a more understandable message
        self.logger.info("Token Validation Status:" + str(r.status_code))
        # todo change the check here
        if 200 <= r.status_code < 300 and len(r.content) > 0:
            return True, str(r.status_code)

        return False, str(r.status_code)
