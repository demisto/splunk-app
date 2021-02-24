import json
import splunk
from json import JSONDecodeError
from six.moves.urllib.parse import quote
from six.moves.urllib.request import pathname2url
from ta_demisto.modalert_create_xsoar_incident_utils import get_incident_occurred_field, get_incident_labels, \
    get_incident_custom_fields

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

    verify = True if helper.get_global_setting('validate_ssl') == '1' else False
    ssl_cert_loc = helper.get_global_setting('ssl_cert_loc')

    server_to_cert = {}
    try:
        server_to_cert = json.loads(str(ssl_cert_loc))
    except JSONDecodeError:
        helper.log_debug('Failed to parse ssl_cert_loc to json, ssl_cert_loc={}'.format(str(ssl_cert_loc)))

    proxy_settings = helper.get_proxy()
    proxy_enabled = bool(proxy_settings)

    events = helper.get_events()
    for event in events:
        helper.log_debug('event = {}'.format(json.dumps(event, indent=4, sort_keys=True)))
        for server_url, api_key in list(servers_to_api_keys.items()):
            server_url = server_url.replace('http:', 'https:')

            try:
                if server_to_cert and server_to_cert.get(server_url):
                    ssl_cert_tmp = server_to_cert.get(server_url)
                else:
                    ssl_cert_tmp = ssl_cert_loc

                incident = create_incident_dictionary(helper, event, search_query, search_name, search_url)

                helper.log_info('Sending the incident to server {}...'.format(server_url))
                headers['Authorization'] = api_key

                helper.log_debug('verify = {}'.format(str(verify)))
                helper.log_debug('ssl_cert_loc = {}'.format(str(ssl_cert_tmp)))
                helper.log_debug('proxy_enabled = {}'.format(str(proxy_enabled)))
                helper.log_debug('payload = {}'.format(json.dumps(incident, indent=4, sort_keys=True)))

                resp = helper.send_http_request(
                    url=server_url + '/incident/splunkapp',
                    method='POST',
                    headers=headers,
                    payload=incident,
                    verify=verify,
                    cert=ssl_cert_tmp,
                    use_proxy=proxy_enabled
                )

                helper.log_debug('resp.status_code = {}'.format(str(resp.status_code)))
                helper.log_debug('resp.content = {}'.format(json.dumps(resp.json(), indent=4, sort_keys=True)))

            except Exception as e:
                helper.log_error(
                    'Failed creating an incident to server {}. Reason: {}'.format(server_url, str(e))
                )
    return 0


def create_incident_dictionary(helper, event, search_query=None, search_name=None, search_url=None):
    occurred = helper.get_param('occurred')
    severity = float(helper.get_param('severity').replace('_', '.'))
    labels = helper.get_param('labels')
    ignore_labels = helper.get_param('ignore_labels')

    # include some search metadata in the rawJSON event dict
    event.update({
        'SplunkURL': search_url,
        'search_name': search_name,
        'SplunkSearch': search_query,
        'name': helper.get_param('incident_name')
    })

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

    helper.log_debug('send_all_servers={}'.format(helper.get_param('send_all_servers')))

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
