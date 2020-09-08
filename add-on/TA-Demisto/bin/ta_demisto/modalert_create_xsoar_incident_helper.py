import json
import time
import splunk
from six.moves.urllib.parse import quote
from six.moves.urllib.request import pathname2url

# encoding = utf-8

ACCOUNTS_ENDPOINT = "/servicesNS/nobody/TA-Demisto/admin/TA_Demisto_account/"


def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]
    [sample_code_macro:end]
    """

    helper.log_info('Alert action create_xsoar_incident started.')

    search_query, search_name, search_url = get_search_data(helper)

    servers_to_api_keys = get_servers_details(helper)

    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json'
    }
    verify = True if helper.get_global_setting('validate_ssl') else False
    ssl_cert_loc = helper.get_global_setting('ssl_cert_loc')

    proxy_settings = helper.get_proxy()
    proxy_enabled = bool(proxy_settings)

    events = helper.get_events()
    for event in events:
        for server_url, api_key in list(servers_to_api_keys.items()):
            try:
                incident = create_incident_dictionary(helper, event, search_query, search_name, search_url)

                helper.log_info('Sending the incident to server {}...'.format(server_url))
                headers['Authorization'] = api_key
                resp = helper.send_http_request(
                    url=server_url + '/incident/splunkapp',
                    method='POST',
                    headers=headers,
                    payload=incident,
                    verify=verify,
                    cert=ssl_cert_loc,
                    use_proxy=proxy_enabled
                )

                helper.log_debug('resp.status_code={}'.format(str(resp.status_code)))
                helper.log_debug('resp.content={}'.format(str(resp.text)))
            except Exception as e:
                helper.log_error(
                    'Failed creating an incident to server {}. Reason: {}'.format(server_url, str(e))
                )

        helper.log_debug('event={}'.format(json.dumps(event, indent=4)))

    return 0


def create_incident_dictionary(helper, event, search_query=None, search_name=None, search_url=None):
    occurred = helper.get_param('occurred')
    severity = float(helper.get_param('severity').replace('_', '.'))
    labels = helper.get_param('labels')
    ignore_labels = helper.get_param('ignore_labels')

    incident = {
        'details': helper.get_param('details'),
        'name': helper.get_param('incident_name'),
        'type': helper.get_param('type'),
        'createInvestigation': True,
        'occurred': get_incident_occurred_field(occurred),
        'severity': severity,
        'rawJSON': json.dumps(event),
        'labels': get_incident_labels(helper, event, labels, ignore_labels,
                                      search_query, search_name, search_url)
    }

    if helper.get_param('custom_fields'):
        incident['CustomFields'] = get_incident_custom_fields(helper.get_param('custom_fields'))

    return incident


def get_incident_labels(helper, event, labels_str, ignore_labels, search_query=None, search_name=None, search_url=None):
    # if labels parameter is not empty, gets only the specified labels.
    # otherwise, gets all the non-ignored labels from Splunk event.
    labels = [
        {'type': 'SplunkSearch', 'value': search_query},
        {'type': 'SplunkURL', 'value': search_url}
    ]

    if search_name:
        labels.append({'type': 'search_name', 'value': search_name})

    if ignore_labels:
        ignore_labels = ignore_labels.strip().lower().split(',')

    helper.log_info('Labels::::' + str(list(event.keys())))
    helper.log_info('Ignored Labels::::' + str(ignore_labels))

    if labels_str:
        labels_str = labels_str.strip().split(',')
        for data_label in labels_str:
            param_data = data_label.split(':')
            labels.append({
                'type': param_data[0],
                'value': ':'.join(param_data[1:])
            })
    else:
        for key in list(event.keys()):
            if (not ignore_labels or key.lower() not in ignore_labels) and not key.startswith('__'):
                labels.append({
                    'type': key,
                    'value': event[key]
                })
    return labels


def get_incident_custom_fields(custom_fields_str):
    str_data = custom_fields_str.strip().split(',')
    custom_fields = {}
    for data in str_data:
        param_data = data.split(':')
        custom_fields[param_data[0]] = ':'.join(param_data[1:])
    return custom_fields


def get_incident_occurred_field(occurred):
    zone = time.strftime('%z')
    timezone = zone[-5:][:3] + ':' + zone[-5:][3:]
    occurred = int(float(occurred))
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(occurred)) + timezone


def get_configured_servers(helper):
    success, content = splunk.rest.simpleRequest(ACCOUNTS_ENDPOINT,
                                                 helper.session_key,
                                                 method='GET',
                                                 getargs={'output_mode': 'json'})

    conf_dict = json.loads(content)
    servers = []

    if success and conf_dict:
        for entry in conf_dict.get('entry', []):
            entry_content = entry.get('content', {})
            servers.append(entry_content.get('username'))

    return servers


def get_servers_details(helper):
    servers_to_api_keys = {}

    helper.log_info('send_all_servers: {}'.format(helper.get_param('send_all_servers')))

    if helper.get_param('send_all_servers') == '1':
        # get all server urls
        servers = get_configured_servers(helper)
    else:
        # use only the selected server url
        server_url = helper.get_param('server_url')
        servers = [server_url]

    for server in servers:
        account = helper.get_user_credential(server)
        api_key = account.get('password')
        servers_to_api_keys[server.strip('/')] = api_key

    return servers_to_api_keys


def get_search_data(helper):
    search_query = None
    search_name = helper.settings.get('search_name')
    results_link = helper.settings.get('results_link')
    search_uri = helper.settings.get('search_uri')

    helper.log_info('Alert name is ' + search_name)
    helper.log_info('Search URI is ' + search_uri)
    helper.log_info('Manually created Search URI is ' + '/services/saved/searches/' + quote(search_name))

    if not search_name:
        helper.log_info('Creating search uri')
        search_app_name = helper.settings.get('app', '')
        if '|' in search_app_name:
            search_name = '//|'.join(search_app_name.split('|'))
        search_uri = pathname2url('/services/saved/searches/' + quote(search_name))

    r = splunk.rest.simpleRequest(search_uri,
                                  sessionKey=helper.session_key,
                                  getargs={'output_mode': 'json'},
                                  method='GET')
    result_op = json.loads(r[1])
    if len(result_op['entry']) > 0:
        search_query = result_op['entry'][0]['content']['qualifiedSearch']

    helper.log_info('Search query is ' + search_query)

    return search_query, search_name, results_link
