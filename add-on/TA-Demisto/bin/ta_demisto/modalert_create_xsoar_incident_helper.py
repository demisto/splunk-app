import json
import os
import traceback
import splunk
import secrets
import string
import hashlib
import configparser
from datetime import timezone, datetime
from six.moves.urllib.parse import quote
from six.moves.urllib.request import pathname2url
from ta_demisto.modalert_create_xsoar_incident_utils import get_incident_occurred_field, get_incident_labels, \
    get_incident_custom_fields

# encoding = utf-8

ACCOUNTS_ENDPOINT = "/servicesNS/nobody/TA-Demisto/admin/TA_Demisto_account/"
conf_file = f'{os.environ.get("SPLUNK_HOME")}/etc/apps/TA-Demisto/default/inputs.conf'

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
    helper.log_debug('Helper params received are: {}'.format(helper.configuration))

    search_query, search_name, search_url = get_search_data(helper)

    servers_to_api_keys = get_servers_details(helper)
    is_cloud = is_cloud_instance(helper)

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
        helper.log_debug('Failed to parse ssl_cert_loc to json, ssl_cert_loc={}'.format(str(ssl_cert_loc)))

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

                if is_cloud:
                    verify = ssl_cert_tmp or True
                else:
                    verify = ssl_cert_tmp if ssl_cert_tmp and verify else verify

                incident = create_incident_dictionary(helper, event, search_query, search_name, search_url)

                helper.log_info('Sending the incident to server {}...'.format(server_url))
                api_key_xsoar_ng = api_key.rsplit('$', 1)
                if len(api_key_xsoar_ng) == 2:
                    nonce = "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(64)])
                    timestamp = str(int(datetime.now(timezone.utc).timestamp()) * 1000)
                    auth_key = "%s%s%s" % (api_key_xsoar_ng[0], nonce, timestamp)
                    auth_key = auth_key.encode("utf-8")
                    api_key_hash = hashlib.sha256(auth_key).hexdigest()
                    headers['x-xdr-auth-id'] = api_key_xsoar_ng[1]
                    headers['Authorization'] = api_key_hash
                    headers['x-xdr-nonce'] = nonce
                    headers['x-xdr-timestamp'] = timestamp
                    server_url += '/xsoar'
                else:
                    headers['Authorization'] = api_key_xsoar_ng[0]

                helper.log_debug('ssl_cert_loc = {}'.format(str(ssl_cert_tmp)))
                helper.log_debug('proxy_enabled = {}'.format(str(proxy_enabled)))
                helper.log_debug('verify = {}'.format(str(verify)))
                helper.log_debug('payload = {}'.format(json.dumps(incident, indent=4, sort_keys=True)))

                resp = helper.send_http_request(
                    url=server_url + '/incident/splunkapp',
                    method='POST',
                    headers=headers,
                    payload=incident,
                    verify=verify,
                    use_proxy=proxy_enabled,
                    timeout=timeout
                )
                helper.log_debug('resp.status_code = {}'.format(str(resp.status_code)))
                try:
                    helper.log_debug('resp.json = {}'.format(json.dumps(resp.json(), indent=4, sort_keys=True)))
                except Exception:
                    helper.log_debug('Could not deserialize response, resp.text = {}'.format(resp.text))

            except Exception as e:
                helper.log_error(traceback.format_exc())
                helper.log_debug('Occurred param is: {}'.format(helper.get_param('occurred')))
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


def is_cloud_instance(helper):
    """
        Returns True if the add-on runs on Splunk cloud, False otherwise.
    """
    # get config file and search is_cloud value.
    config = configparser.ConfigParser()
    config.read(conf_file)
    helper.log_info(config.sections())

    if config.has_section('default') and config.get('default', 'is_cloud') != "None":
        # We checked before if the instance is cloud and return what saved in the config file.
        is_cloud = config.get('default', 'is_cloud')
        helper.log_info(f'Got value from storage for instance type. The value is {is_cloud}')
        if is_cloud == 'False':
            return False
        return True

    try:
        server_info_uri = pathname2url('/services/server/info')
        r = splunk.rest.simpleRequest(server_info_uri,
                                      sessionKey=helper.session_key,
                                      getargs={'output_mode': 'json'},
                                      method='GET')
        result_info = json.loads(r[1])
        helper.log_debug(f'Got server info from Splunk: {str(result_info)}')
        instance_type = result_info.get('instance_type')
        if instance_type and instance_type == 'cloud':
            helper.log_info('Running on cloud.')
            is_cloud = True
        else:
            helper.log_info('Running on enterprise.')
            is_cloud = False

        config.set("default", "is_cloud", str(is_cloud))
        with open(conf_file, "w") as config_file:
            config.write(config_file)

        return is_cloud
    except Exception as e:
        # if we fail to get the instance type from the server we return True to set the request to verify True.
        helper.log_error(
            'Failed getting instance type from server, acting as cloud instance. Reason: {}'.format(str(e))
        )
        return True


def get_configured_servers(helper):
    success, content = splunk.rest.simpleRequest(ACCOUNTS_ENDPOINT,
                                                 helper.session_key,
                                                 method='GET',
                                                 getargs={'output_mode': 'json'})

    conf_dict = json.loads(content)
    if not isinstance(conf_dict, dict):
        raise TypeError('Invalid content from TA_Demisto_account. conf_dict = {}'.format(conf_dict))
    servers = []

    if success and conf_dict:
        for entry in conf_dict.get('entry', []):
            if not isinstance(entry, dict):
                raise TypeError('Invalid content from TA_Demisto_account. entry = {}'.format(entry))

            entry_content = entry.get('content', {})
            if not isinstance(entry_content, dict):
                raise TypeError('Invalid content from TA_Demisto_account. entry_content = {}'.format(entry_content))

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

    helper.log_debug(f"servers are: {str(servers)}")
    for server in servers:
        helper.log_debug(f"current server is: {str(server)}")
        account = helper.get_user_credential(server)

        if not isinstance(account, dict):
            raise TypeError('Invalid type. account = {}'.format(account))

        api_key = account.get('password')
        servers_to_api_keys[server.strip('/')] = api_key

    return servers_to_api_keys


def get_search_data(helper):
    search_query = ''

    if not isinstance(helper.settings, dict):
        raise TypeError('Invalid type. helper.settings = {}'.format(helper.settings))

    search_name = helper.settings.get('search_name', '')
    results_link = helper.settings.get('results_link', '')
    search_uri = helper.settings.get('search_uri', '')

    helper.log_info('Alert name is {}'.format(search_name))
    helper.log_info('Search URI is {}'.format(search_uri))
    helper.log_info('Manually created Search URI is /services/saved/searches/{}'.format(quote(search_name)))

    if not search_name:
        helper.log_info('Creating search uri')
        search_app_name = helper.settings.get('app', '')
        if '|' in search_app_name:
            search_name = '//|'.join(search_app_name.split('|'))
        search_uri = pathname2url('/services/saved/searches/{}'.format(quote(search_name)))

    r = splunk.rest.simpleRequest(search_uri,
                                  sessionKey=helper.session_key,
                                  getargs={'output_mode': 'json'},
                                  method='GET')
    result_op = json.loads(r[1])
    if len(result_op['entry']) > 0:
        search_query = result_op['entry'][0]['content']['qualifiedSearch']

    helper.log_info('Search query is {}'.format(search_query))

    return search_query, search_name, results_link
