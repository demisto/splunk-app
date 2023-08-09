import json
import traceback
import splunk
import secrets
import string
import hashlib
from datetime import timezone, datetime
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
    helper.log_debug(f'Helper params received are: {helper.configuration}')

    search_query, search_name, search_url = get_search_data(helper)

    servers_to_api_keys = get_servers_details(helper)

    headers = {
        'Content-type': 'application/json',
        'Accept': 'application/json'
    }

    verify = True if helper.get_global_setting('validate_ssl') == '1' else False
    ssl_cert_loc = helper.get_global_setting('ssl_cert_loc')
    timeout = helper.get_global_setting('timeout_val')
    timeout = int(timeout) if timeout else None
    helper.log_debug(f'request timeout is {timeout}')

    server_to_cert = {}
    try:
        server_to_cert = json.loads(str(ssl_cert_loc))
    except ValueError:
        helper.log_debug(
            f'Failed to parse ssl_cert_loc to json, ssl_cert_loc={str(ssl_cert_loc)}'
        )

    proxy_settings = helper.get_proxy()
    proxy_enabled = bool(proxy_settings)

    events = helper.get_events()
    for event in events:
        helper.log_debug('event = {}'.format(json.dumps(event, indent=4, sort_keys=True)))
        for server_url, api_key in list(servers_to_api_keys.items()):
            server_url = server_url.replace('http:', 'https:')

            try:
                if isinstance(server_to_cert, dict) and server_to_cert.get(server_url):
                    ssl_cert_tmp = server_to_cert.get(server_url)
                else:
                    ssl_cert_tmp = ssl_cert_loc

                incident = create_incident_dictionary(helper, event, search_query, search_name, search_url)

                helper.log_info(f'Sending the incident to server {server_url}...')
                api_key_xsoar_ng = api_key.rsplit('$', 1)
                if len(api_key_xsoar_ng) == 2:
                    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
                    timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
                    auth_key = f"{api_key_xsoar_ng[0]}{nonce}{timestamp}"
                    auth_key = auth_key.encode("utf-8")
                    api_key_hash = hashlib.sha256(auth_key).hexdigest()
                    headers['x-xdr-auth-id'] = api_key_xsoar_ng[1]
                    headers['Authorization'] = api_key_hash
                    headers['x-xdr-nonce'] = nonce
                    headers['x-xdr-timestamp'] = timestamp
                    server_url += '/xsoar'
                else:
                    headers['Authorization'] = api_key_xsoar_ng[0]

                helper.log_debug(f'verify = {verify}')
                helper.log_debug(f'ssl_cert_loc = {str(ssl_cert_tmp)}')
                helper.log_debug(f'proxy_enabled = {proxy_enabled}')
                helper.log_debug('payload = {}'.format(json.dumps(incident, indent=4, sort_keys=True)))

                resp = helper.send_http_request(
                    url=server_url + '/incident/splunkapp',
                    method='POST',
                    headers=headers,
                    payload=incident,
                    verify=ssl_cert_tmp if ssl_cert_tmp and verify else verify,
                    use_proxy=proxy_enabled,
                    timeout=timeout
                )
                helper.log_debug(f'resp.status_code = {str(resp.status_code)}')
                try:
                    helper.log_debug('resp.json = {}'.format(json.dumps(resp.json(), indent=4, sort_keys=True)))
                except Exception:
                    helper.log_debug(f'Could not deserialize response, resp.text = {resp.text}')

            except Exception as e:
                helper.log_error(traceback.format_exc())
                helper.log_debug(f"Occurred param is: {helper.get_param('occurred')}")
                helper.log_error(
                    f'Failed creating an incident to server {server_url}. Reason: {str(e)}'
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
    if not isinstance(conf_dict, dict):
        raise TypeError(
            f'Invalid content from TA_Demisto_account. conf_dict = {conf_dict}'
        )
    servers = []

    if success and conf_dict:
        for entry in conf_dict.get('entry', []):
            if not isinstance(entry, dict):
                raise TypeError(f'Invalid content from TA_Demisto_account. entry = {entry}')

            entry_content = entry.get('content', {})
            if not isinstance(entry_content, dict):
                raise TypeError(
                    f'Invalid content from TA_Demisto_account. entry_content = {entry_content}'
                )

            servers.append(entry_content.get('username'))
    return servers


def get_servers_details(helper):
    servers_to_api_keys = {}

    helper.log_debug(f"send_all_servers={helper.get_param('send_all_servers')}")

    if helper.get_param('send_all_servers') == '1':
        # get all server urls
        servers = get_configured_servers(helper)
    else:
        # use only the selected server url
        server_url = helper.get_param('server_url')
        servers = [server_url]

    helper.log_debug(f"servers are: {str(servers)}")
    for server in servers:
        helper.log_debug(f"current server is: {str(server)}")
        account = helper.get_user_credential(server)

        if not isinstance(account, dict):
            raise TypeError(f'Invalid type. account = {account}')

        api_key = account.get('password')
        servers_to_api_keys[server.strip('/')] = api_key

    return servers_to_api_keys


def get_search_data(helper):
    search_query = ''

    if not isinstance(helper.settings, dict):
        raise TypeError(f'Invalid type. helper.settings = {helper.settings}')

    search_name = helper.settings.get('search_name', '')
    results_link = helper.settings.get('results_link', '')
    search_uri = helper.settings.get('search_uri', '')

    helper.log_info(f'Alert name is {search_name}')
    helper.log_info(f'Search URI is {search_uri}')
    helper.log_info(
        f'Manually created Search URI is /services/saved/searches/{quote(search_name)}'
    )

    if not search_name:
        helper.log_info('Creating search uri')
        search_app_name = helper.settings.get('app', '')
        if '|' in search_app_name:
            search_name = '//|'.join(search_app_name.split('|'))
        search_uri = pathname2url(f'/services/saved/searches/{quote(search_name)}')

    r = splunk.rest.simpleRequest(search_uri,
                                  sessionKey=helper.session_key,
                                  getargs={'output_mode': 'json'},
                                  method='GET')
    result_op = json.loads(r[1])
    if len(result_op['entry']) > 0:
        search_query = result_op['entry'][0]['content']['qualifiedSearch']

    helper.log_info(f'Search query is {search_query}')

    return search_query, search_name, results_link
