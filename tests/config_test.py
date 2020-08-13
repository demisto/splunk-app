from pytest_splunk_addon.standard_lib.addon_basic import Basic


class TestApp(Basic):
    def empty_method(self):
        assert 1 == 1
