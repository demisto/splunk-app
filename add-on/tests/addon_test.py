import json
import time

from demisto_helpers import get_demisto_config_from_response
from lib.demisto_incident import DemistoIncident


class MockLogger:
    def __init__(self):
        self.info_data = []
        self.debug_data = []

    def info(self, msg):
        self.info_data.append(msg)

    def debug(self, msg):
        self.debug_data.append(msg)


def test_create_incident_dictionary_with_labels():
    """
        Given:
            A valid incident settings configuration that contains comma-separated labels
        When:
            Calling create_incident_dictionary function
        Then:
            Verify the function output is a valid demisto incident dictionary, by checking:
            - The labels were inserted correctly into the incident labels attribute.
            - The SplunkURL, search_name and SplunkSearch labels are empty/None.
    """
    with open('add-on/tests/test_data/incident_config_with_labels.json', 'r') as f:
        data = json.loads(f.read())
        demisto_incident = DemistoIncident(logger=MockLogger())
        incident = demisto_incident.create_incident_dictionary(data=data)
        assert len(incident['labels']) == 4
        assert get_label_value_by_type(incident['labels'], 'SplunkSearch') == ''
        assert get_label_value_by_type(incident['labels'], 'search_name') is None
        assert get_label_value_by_type(incident['labels'], 'SplunkURL') == ''
        assert get_label_value_by_type(incident['labels'], 'key1') == 'value1'
        assert get_label_value_by_type(incident['labels'], 'key2') == 'value2'


def test_create_incident_dictionary_no_labels():
    """
        Given:
            - A valid incident settings configuration that contains:
                - three customFields (comma-separated string)
                - an `occurred` timestamp
                - A severity attribute with the value "2"
            - A splunk search query
            - A splunk search URL
            - A splunk search name
        When:
            Calling create_incident_dictionary function
        Then:
            Verify the function output is a valid demisto incident dictionary, by checking:
            - The customFields were parsed correctly
            - The `occurred` attribute was parsed to a valid date string
            - The `severity` attribute was parsed to a valid float
            - The splunk search query, search URL and search name were inserted to the incident labels.
    """
    with open('add-on/tests/test_data/incident_config_no_labels.json', 'r') as f:
        data = json.loads(f.read())

        demisto_incident = DemistoIncident(logger=MockLogger())
        incident = demisto_incident.create_incident_dictionary(data=data,
                                                               search_query='mock_search_query',
                                                               search_url='https://test.com',
                                                               search_name='mock_search_name')
        assert len(incident['customFields'].items()) == 3
        assert '2020-08-20' in incident['occurred']
        assert incident['severity'] == 2.0
        assert get_label_value_by_type(incident['labels'], 'SplunkSearch') == 'mock_search_query'
        assert get_label_value_by_type(incident['labels'], 'SplunkURL') == 'https://test.com'
        assert get_label_value_by_type(incident['labels'], 'search_name') == 'mock_search_name'


def test_create_incident_dictionary_with_result_argument():
    """
        Given:
            - A valid incident settings configuration that contains an `ignore_labels` attribute (:=`key1,key2`)
        When:
            Calling create_incident_dictionary function with a `result` argument
        Then:
            Verify the function output is a valid demisto incident dictionary, by checking:
            - The labels (key1, key2) in ignore_labels attributes weren't inserted to the incident labels.
            - The incident rawJSON is populated by the result data.
    """
    with open('add-on/tests/test_data/incident_config_no_labels.json', 'r') as f:
        data = json.loads(f.read())

        result = {
            'key1': 'value1',
            'key2': 'value2',
            'key3': 'value3'
        }

        demisto_incident = DemistoIncident(logger=MockLogger())
        incident = demisto_incident.create_incident_dictionary(data=data, result=result)
        assert get_label_value_by_type(incident['labels'], 'key1') is None
        assert get_label_value_by_type(incident['labels'], 'key2') is None
        assert get_label_value_by_type(incident['labels'], 'key3') == 'value3'


def get_label_value_by_type(labels, label_type):
    for label in labels:
        if label.get('type') == label_type:
            return label.get('value')
    return None


def test_get_demisto_config_from_response_good():
    """
        Given:
            A successful response of demisto config response splunk get request
            that contains config attributes such as 'DEMISTOURL', 'config' and ''
        When:
            Calling get_demisto_config_from_response function
        Then:
            Verify the configuration is retrieved correctly by checking the value of 'DEMISTOURL' field
            and verifying that '' and 'config' attributes are not in the function output
    """
    with open('add-on/tests/test_data/demisto_conf_resp.json', 'r') as f:
        resp = f.read()
        config = get_demisto_config_from_response(success=True, content=resp)
        assert config.get('DEMISTOURL') == 'https://test.com'
        assert '' not in config
        assert 'config' not in config


def test_get_config_from_response_bad():
    """
        Given:
            An unsuccessful response of demisto config response splunk get request
        When:
            Calling get_demisto_config_from_response function
        Then:
            Verify the function output is an empty dict
    """
    resp = json.dumps({'msg': 'bad_resp'})
    config = get_demisto_config_from_response(success=False, content=resp)
    assert len(config.items()) == 0
