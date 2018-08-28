#!/usr/bin/env python

#
# This code was written by Demisto Inc.
#

import json
import time
import requests
from requests import Request


class DemistoIncident():
    def __init__(self, logger):
        """
        :rtype: object
        """
        self.logger = logger

    def create_incident(self, authkey, data, verify_req, search_query="", search_url="", ssl_cert_loc="",
                        result=None,
                        search_name=None,
                        proxies=None):
        """
            This method is used to create incident in Demisto. It takes four arguments and all are mandatory:
            @url: Demisto URL, its mandatory parameter.
            @authkey: Requires parameter, used for authentication.
            @data: Incident information,
            @verify: Indicates if self signed certificates are allowed or not.
        """

        incident = self.create_incident_dictionary(data, search_query, search_url, result, search_name)

        s = requests.session()

        self.logger.debug("JSON data for the Incident=" + json.dumps(incident))

        url = data.get('demisto_server', '')
        req = Request('POST', url + "/incident/splunkapp", data=json.dumps(incident))
        prepped = s.prepare_request(req)

        prepped.headers['Authorization'] = authkey
        prepped.headers['Content-type'] = "application/json"
        prepped.headers['Accept'] = "application/json"

        if ssl_cert_loc:
            self.logger.info("In create_incident, setting passed certificate location as verify=" + ssl_cert_loc)
            resp = s.send(prepped, verify=ssl_cert_loc, proxies=proxies)
        else:
            self.logger.info("In create_incident, using verify = " + str(verify_req))
            resp = s.send(prepped, verify=verify_req, proxies=proxies)

        return resp

    def create_incident_dictionary(self, data, search_query="", search_url="", result=None, search_name=None):
        incident = {}

        incident["details"] = data.get('details', '')

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

        if data.get("labels"):
            str_data = data["labels"].split(",")
            for data_label in str_data:
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
            str_data = data["custom_field"].split(",")
            custom_fields = {}
            for data in str_data:
                param_data = data.split(":")
                custom_fields[param_data[0]] = ":".join(param_data[1:])

            incident["customFields"] = custom_fields

        incident["rawJSON"] = json.dumps(result)

        return incident
