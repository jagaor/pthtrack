import pytest

from src.detector import PthDetector


@pytest.fixture
def ecs_ntlm_network():
    return {
        "event": {"code": "4624", "action": "logon-success"},
        "winlog": {
            "logon": {"type": 3, "auth_package": "NTLM"},
        },
        "user": {"name": "jsmith"},
        "source": {"ip": "10.0.0.42"},
        "host": {"name": "WS-01"},
        "@timestamp": "2024-03-01T10:15:00Z",
    }


@pytest.fixture
def ecs_anonymous():
    return {
        "event": {"code": "4624", "action": "logon-success"},
        "winlog": {
            "logon": {"type": 3, "auth_package": "NTLM"},
        },
        "user": {"name": "ANONYMOUS LOGON"},
        "source": {"ip": "10.0.0.99"},
        "host": {"name": "DC-01"},
        "@timestamp": "2024-03-01T10:16:00Z",
    }


@pytest.fixture
def ecs_4648_null_sid():
    return {
        "event": {"code": "4648", "action": "explicit-credential-logon"},
        "winlog": {
            "subject": {"sid": "S-1-0-0", "user_name": "-"},
            "logon": {"type": 9, "auth_package": "Negotiate"},
        },
        "user": {"name": "svc_backup"},
        "source": {"ip": "10.0.0.77"},
        "host": {"name": "SRV-02"},
        "@timestamp": "2024-03-01T10:17:00Z",
    }


@pytest.fixture
def ecs_clean():
    return {
        "event": {"code": "4624", "action": "logon-success"},
        "winlog": {
            "logon": {"type": 2, "auth_package": "Kerberos"},
        },
        "user": {"name": "admin"},
        "source": {"ip": "10.0.0.10"},
        "host": {"name": "WS-05"},
        "@timestamp": "2024-03-01T10:18:00Z",
    }


@pytest.fixture
def detector():
    return PthDetector()


def test_ntlm_network_logon_detected(detector, ecs_ntlm_network):
    alerts = detector.analyze([ecs_ntlm_network])
    assert len(alerts) == 1
    assert alerts[0].rule_name == "NTLM_LOGON_4624_TYPE3"
    assert alerts[0].severity == "HIGH"


def test_anonymous_logon_critical(detector, ecs_anonymous):
    alerts = detector.analyze([ecs_anonymous])
    assert len(alerts) >= 1
    assert any(a.severity == "CRITICAL" for a in alerts)


def test_null_sid_4648_critical(detector, ecs_4648_null_sid):
    alerts = detector.analyze([ecs_4648_null_sid])
    assert len(alerts) >= 1
    assert any(a.severity == "CRITICAL" for a in alerts)


def test_clean_event_no_alert(detector, ecs_clean):
    alerts = detector.analyze([ecs_clean])
    assert alerts == []


def test_multiple_events_multiple_alerts(detector, ecs_ntlm_network, ecs_anonymous):
    alerts = detector.analyze([ecs_ntlm_network, ecs_anonymous])
    assert len(alerts) == 2


def test_mitre_technique_present(detector, ecs_ntlm_network, ecs_anonymous, ecs_4648_null_sid):
    alerts = detector.analyze([ecs_ntlm_network, ecs_anonymous, ecs_4648_null_sid])
    assert len(alerts) >= 1
    for alert in alerts:
        assert alert.mitre_technique == "T1550.002"
