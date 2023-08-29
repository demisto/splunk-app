from ta_demisto.modalert_create_xsoar_incident_utils import get_incident_occurred_field, get_incident_labels, \
    get_incident_custom_fields
from ta_demisto.modalert_create_xsoar_incident_helper import is_cloud_instance

class MockHelper:
    def __init__(self):
        self.info_data = []
        self.debug_data = []

    def log_info(self, msg):
        self.info_data.append(msg)

    def log_debug(self, msg):
        self.debug_data.append(msg)

class MockParser:
    def read(self, file):
        pass

    def has_section(self, section):
        return True

    def get(self, section, key):
        return 'None'

    def set(self, section, key, value):
        pass
def test_get_incident_labels__empty_labels_string():
    """
        Given:
            - A valid event dictionary
            - An empty labels string attribute of an alert action
            - An valid ignore_labels string attribute of an alert action
        When:
            Calling get_incident_labels function
        Then:
            - Verify the event labels are returned into a valid incident labels list of dictionaries of the form:
              {'type': <label_type>, 'value': <label_value>}
            - Verify the labels mentioned in ignore_labels string aren't included in the output.
    """
    event = {
        'test_key1': 'test_val1',
        'test_key2': 'test_val2',
        'test_key3': 'test_val3',
        'test_key4': 'test_val4'
    }
    labels_str = ''
    ignore_labels = 'test_key2,test_key3'

    labels = get_incident_labels(MockHelper(), event, labels_str, ignore_labels)
    labels_types = [label.get('type') for label in labels]

    assert 'test_key1' in labels_types
    assert 'test_key2' not in labels_types
    assert 'test_key3' not in labels_types
    assert 'test_key4' in labels_types


def test_get_incident_labels__with_labels_string_and_search_data():
    """
        Given:
            - A valid event dictionary
            - A valid labels string attribute of an alert action
            - Search data (search_name, search_url, search_query)
        When:
            Calling get_incident_labels function
        Then:
            - Verify the labels in the string are inserted to the labels dictionary.
            - Verify none of the fields in the event dictionary is in the labels dictionary.
            - Verify the search data is inserted to the labels dictionary correctly.
    """
    event = {
        'test_key1': 'test_val1',
        'test_key2': 'test_val2'
    }
    labels_str = 'label1:value1,label2:value2:value2.1'
    ignore_labels = ''
    search_query, search_name, search_url = 'search_query', 'search_name', 'search_url'

    labels = get_incident_labels(MockHelper(), event, labels_str, ignore_labels, search_query, search_name, search_url)
    labels_types = [label.get('type') for label in labels]
    labels_values = [label.get('value') for label in labels]

    assert 'test_key1' not in labels_types
    assert 'test_key2' not in labels_types

    assert 'label1' in labels_types
    assert 'label2' in labels_types

    assert 'value1' in labels_values
    assert 'value2:value2.1' in labels_values

    assert 'SplunkSearch' in labels_types
    assert 'SplunkURL' in labels_types
    assert 'search_name' in labels_types

    assert 'search_query' in labels_values
    assert 'search_url' in labels_values
    assert 'search_name' in labels_values


def test_get_incident_custom_fields():
    """
        Given:
            A valid custom_fields string attribute of an alert action
        When:
            Calling get_incident_custom_fields function
        Then:
            Verify the output is parsed to a valid dictionary of incident custom fields.
    """
    custom_fields_str = 'killchain:1.1.1.1,User:john'

    incident_custom_fields = get_incident_custom_fields(custom_fields_str)
    assert len(incident_custom_fields) == 2
    assert 'killchain' in incident_custom_fields
    assert incident_custom_fields['killchain'] == '1.1.1.1'
    assert 'User' in incident_custom_fields
    assert incident_custom_fields['User'] == 'john'


def test_get_incident_occurred_field():
    """
        Given:
            A valid occurred string attribute of an alert action in epoch format
        When:
            Calling get_incident_occurred_field function
        Then:
            Verify the output is parsed to a valid incident occurred field in the format '%Y-%m-%dT%H:%M:%S'.
    """
    occurred_str = '1599591202'
    occurred = get_incident_occurred_field(occurred_str)
    assert occurred == '2020-09-08T18:53:22+00:00'

def test_is_cloud_instance(mocker):
    res_cloud = {
        "instance_type": "cloud"
    }
    res_not_cloud = {
        "instance_type": "not cloud"
    }

    mocker.patch.object(configparser, 'ConfigParser', MockParser)
    mocker.patch('splunk.rest.simpleRequest', return_value=[None, res_cloud])
    assert is_cloud_instance(MockHelper())

    mocker.patch('splunk.rest.simpleRequest', return_value=[None, res_not_cloud])
    assert not is_cloud_instance(MockHelper())
