import sys
from unittest.mock import Mock

sys.modules['splunk'] = Mock()


def test_demisto_servers():
    from demisto_servers import get_servers_from_response
    pass


def test_demisto_action():
    from demisto_send_alert import get_config_from_response
    pass


def test_get_validate_ssl_value_from_response():
    from demisto_setup import get_validate_ssl_value_from_response
    pass
