from ta_demisto.modalert_create_xsoar_incident_utils import get_incident_occurred_field, get_incident_labels, \
    get_incident_custom_fields


class MockHelper:
    def __init__(self):
        self.info_data = []
        self.debug_data = []

    def log_info(self, msg):
        self.info_data.append(msg)

    def log_debug(self, msg):
        self.debug_data.append(msg)


def test_get_incident_labels__empty_labels_string():
    """
        Given:
            - A valid event dictionary
            - An empty labels string attribute of an alert action
            - An valid ignore_labels string attribute of an alert action
        When:
            Calling get_incident_labels function
        Then:
            - Verify the event labels are returned into a valid incident labels dictionary.
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
    assert 'test_key1' in labels
    assert 'test_key2' not in labels
    assert 'test_key3' not in labels
    assert 'test_key4' in labels


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
            - Verify non of the fields in the event dictionary is not in the labels dictionary.
            - Verify the search data is inserted to the labels dictionary.
    """
    event = {
        'test_key1': 'test_val1',
        'test_key2': 'test_val2'
    }
    labels_str = 'label1:value1,label2:value2:value2.1'
    ignore_labels = ''
    search_query, search_name, search_url = 'search_query', 'search_name', 'search_url'

    labels = get_incident_labels(MockHelper(), event, labels_str, ignore_labels, search_query, search_name, search_url)
    assert 'test_key1' not in labels
    assert 'test_key2' not in labels
    assert 'label1' in labels
    assert labels['label1'] == 'value1'
    assert 'label2' in labels
    assert labels['label2'] == 'value2:value2.1'


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
    assert occurred == '2020-09-08T21:53:22'
