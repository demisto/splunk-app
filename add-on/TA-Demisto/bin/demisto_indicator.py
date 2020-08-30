"""Demisto class to define an indicator."""
# !/usr/bin/env python

import base64
import json
import requests
from requests import Request


class DemistoIndicator():
    """Demisto class defining an indicator."""

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

    def create_indicator(
            self,
            authkey,
            indicator,
            indicator_type,
            reputation,
            comment,
            verify_req,
            ssl_cert_loc="",
            proxies=None,
            url=None,
            beyond_corp_key="",
            beyond_corp_secret="",
            beyond_corp_api=""):
        """Method is used to create indicator in Demisto."""
        try:
            entry = {}
            entry['indicator'] = {'value': indicator,
                                  'indicator_type': indicator_type,
                                  'score': int(reputation),
                                  'comment': comment,
                                  'source': 'SplunkApp'}
            entry['seenNow'] = True

            splunk_session = requests.session()

            self.logger.debug("JSON data for the Indicator=" + json.dumps(entry))

            req = Request('POST', url + "/indicator/create", data=json.dumps(entry))
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
                    "In create_indicator, setting passed certificate location as verify=" + ssl_cert_loc
                )
                resp = splunk_session.send(prepped, verify=ssl_cert_loc, proxies=proxies)
            else:
                self.logger.info("In create_indicator, using verify = " + str(verify_req))
                resp = splunk_session.send(prepped, verify=verify_req, proxies=proxies)

            return resp
        except Exception as ex:
            raise ex
