import sys
import unittest
from unittest.mock import Mock, patch, PropertyMock


class MockSplunkCliLib:
    @staticmethod
    def make_splunkhome_path(lst):
        return '/'.join(lst)


sys.modules['splunk'] = Mock()
sys.modules['splunk.rest'] = Mock()
sys.modules['splunk.clilib'] = Mock()
sys.modules['splunk.clilib.bundle_paths'] = Mock(spec_set=MockSplunkCliLib)
sys.modules['splunk.appserver.mrsparkle.lib.util'] = Mock(spec_set=MockSplunkCliLib)
sys.modules['splunk.admin'] = Mock()
sys.modules['splunk.util'] = Mock()
sys.modules['splunk.version'] = Mock()


class TestAddon(unittest.TestCase):
    splunk_version_mock = Mock(return_value="6.5.0")

    def test_demisto_servers(self):
        from demisto_servers import get_servers_from_response
        pass

    @patch(target='splunk.version.__version__', new=splunk_version_mock)
    def test_demisto_action(self):
        from demisto_send_alert import get_config_from_response
        pass

    @patch(target='splunk.version.__version__', new=splunk_version_mock)
    def test_get_validate_ssl_value_from_response(self):
        from demisto_setup import get_validate_ssl_value_from_response
        pass
