import json

from demisto_helpers import get_config_from_response


def test_get_config_from_response_good_response():
    with open('add-on/tests/test_data/config_response.json', 'r') as f:
        resp = f.read()
        config = get_config_from_response(success=True, content=resp)
        assert config.get('DEMISTOURL') == 'https://test.com'
        assert '' not in config
        assert 'config' not in config


def test_get_config_from_response_bad_response():
    resp = json.dumps({'msg': 'bad_resp'})
    config = get_config_from_response(success=False, content=resp)
    assert len(config.items()) == 0
