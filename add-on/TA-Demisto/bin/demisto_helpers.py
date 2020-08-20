import json


def get_config_from_response(success, content):
    conf_dic = json.loads(content)
    config = {}
    if success and conf_dic:
        for entry in conf_dic.get('entry', []):
            val = entry.get('content', {})
            if val:
                config = val
    if '' in config:
        config.pop('')
    if 'config' in config:
        config.pop('config')

    return config
