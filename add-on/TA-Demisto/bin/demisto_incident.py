"""Demisto class to define an incident."""
# !/usr/bin/env python

#
# This code was written by Demisto Inc.
#
import base64
import json
import time
import requests
from requests import Request


class DemistoIncident():
    """Demisto class defining an incident."""

    def __init__(self, logger):
        """:rtype: object."""
        self.logger = logger

    def fetch_beyondcorp_token(self, beyond_corp_key="", beyond_corp_secret="", beyond_corp_api=""):
        """Function that posts to beyondcorp and gets back key/secret."""
        try:
            headers = {
                'Authorization': 'Basic {}'.format(base64.b64encode("{}:{}".format(
                    beyond_corp_key, beyond_corp_secret
                )))
            }
            res = requests.post('https://' + beyond_corp_api, headers=headers)
            res.raise_for_status()
            self.logger.info("Successfully fetched BeyondCorp Token")
            return res.json().get("access_token")
        except Exception as ex:
            raise ex

    def create_incident(
            self,
            authkey,
            data,
            verify_req,
            search_query="",
            search_url="",
            ssl_cert_loc="",
            result=None,
            search_name=None,
            proxies=None,
            url=None,
            beyond_corp_key="",
            beyond_corp_secret="",
            beyond_corp_api=""):
        """Method is used to create incident in Demisto.

        It takes four arguments and all are mandatory:
            @url: Demisto URL, its mandatory parameter.
            @authkey: Requires parameter, used for authentication.
            @data: Incident information,
            @verify_req: Indicates if we should use SSL
        """
        try:
            incident = self.create_incident_dictionary(
                data,
                search_query,
                search_url,
                result,
                search_name
            )

            splunk_session = requests.session()

            self.logger.debug("JSON data for the Incident=" + json.dumps(incident))

            req = Request('POST', url + "/incident/splunkapp", data=json.dumps(incident))
            prepped = splunk_session.prepare_request(req)

            prepped.headers['Authorization'] = authkey
            prepped.headers['Content-type'] = "application/json"
            prepped.headers['Accept'] = "application/json"
            if(len(str(beyond_corp_api)) > 0 and "https" in str(beyond_corp_api)):
                prepped.headers['lum-api-token'] = self.fetch_beyondcorp_token(
                    beyond_corp_key,
                    beyond_corp_secret,
                    beyond_corp_api
                )

            if ssl_cert_loc and verify_req:
                self.logger.info(
                    "In create_incident, setting passed certificate location as verify=" + ssl_cert_loc
                )
                resp = splunk_session.send(prepped, verify=ssl_cert_loc, proxies=proxies)
            else:
                self.logger.info("In create_incident, using verify = " + str(verify_req))
                resp = splunk_session.send(prepped, verify=verify_req, proxies=proxies)

            return resp
        except Exception as ex:
            raise ex

    def create_incident_dictionary(
            self,
            data,
            search_query="",
            search_url="",
            result=None,
            search_name=None):
        """Function to create a dict for the incident."""
        try:
            incident = {}

            incident["details"] = data.get('details', '')

            zone = time.strftime("%z")
            timezone = zone[-5:][:3] + ":" + zone[-5:][3:]

            incident["occurred"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S",
                time.localtime(int(float(data["occured"])))) + timezone

            # Always pass True for create investigation
            incident["createInvestigation"] = True

            incident["name"] = data.get('incident_name', '')

            incident["type"] = data.get('type', '')

            ignore_labels = data.get('ignore_labels', '').strip().lower().split(",")

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

            self.logger.debug("Label::::" + str(list(result.keys())))
            self.logger.debug("Ignore Label::::" + str(ignore_labels))

            if data.get("labels"):
                str_data = data["labels"].strip().split(",")
                for data_label in str_data:
                    param_data = data_label.split(":")
                    data_dir = {"type": param_data[0], "value": ":".join(param_data[1:])}
                    labels.append(data_dir)
            else:
                for key in list(result.keys()):
                    if key.lower() not in ignore_labels and not key.startswith("__"):
                        data_dir = {"type": key, "value": result[key]}
                        labels.append(data_dir)

            incident["labels"] = labels

            if "custom_field" in data:
                # str_data = data["custom_field"].strip().split(",")
                str_data = self.split_fields(data["custom_field"].strip())
                custom_fields = {}
                for data_item in str_data:
                    param_data = data_item.split(":")
                    custom_fields[param_data[0]] = ":".join(param_data[1:])

                incident["customFields"] = custom_fields

            incident["rawJSON"] = json.dumps(result)

            return incident
        except Exception as ex:
            raise ex

    def split_fields(self, s):
        """Function to split fields."""
        colon = 0
        comma = 0
        pointer = 0
        counter = 0
        nested_json = 0
        last_comma_position = -1
        position = []
        str_data = []

        for char in s:

            # beginning of nest json
            counter = counter + 1
            if char == '{':
                nested_json = nested_json + 1

            # end of nested json
            if char == '}':
                nested_json = nested_json - 1

            if char == ',':
                comma = comma + 1

                # keep track of potential split location
                if colon > 0 and nested_json == 0:
                    last_comma_position = counter

            if char == ':':
                colon = colon + 1

                # split location found (comma before colon)
                if comma > 0 and not last_comma_position == -1 and nested_json == 0:
                    position.append(last_comma_position)
                    last_comma_position = -1
                    comma = 0
                    colon = colon - 1

        # add the end of string to the position array
        position.append(counter + 1)

        for p in position:
            str_data.append(s[pointer:p - 1])
            pointer = p

        return str_data
