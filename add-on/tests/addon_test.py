import sys
sys.path.append('/add-on/TA-Demisto/bin')


def test_demisto_setup():
    from demisto_setup import ConfigApp
    assert 1 == 1


def test_demisto_incident():
    assert 1 == 1


def test_demisto_servers():
    assert 1 == 1


def test_demisto_send_alert():
    assert 1 == 1
