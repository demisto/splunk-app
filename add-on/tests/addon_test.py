import sys
from unittest.mock import Mock

sys.modules['splunk'] = Mock()
sys.modules['splunk.rest'] = Mock()
sys.modules['splunk.clilib'] = Mock()
# sys.modules['splunk.clilib.bundle_paths.make_splunkhome_path'] = Mock()
# sys.modules['splunk.appserver.mrsparkle.lib.util.make_splunkhome_path'] = Mock()
sys.modules['splunk.appserver'] = Mock()
sys.modules['splunk.admin'] = Mock()
sys.modules['splunk.version'] = Mock()
sys.modules['splunk.version.__version__'] = Mock()
sys.modules['splunk.util'] = Mock()


def test_demisto_servers():
    from demisto_servers import get_servers_from_response
    pass


def test_demisto_action():
    from demisto_send_alert import get_config_from_response
    pass


def test_get_validate_ssl_value_from_response():
    from demisto_setup import get_validate_ssl_value_from_response
    pass
