import pytest
from datetime import datetime, timezone

from src.normalizer import EventNormalizer, WindowsEvent


@pytest.fixture
def raw_event_4624():
    """Evento 4624 (logon exitoso) con todos los campos relevantes."""
    return {
        "EventID": 4624,
        "TimeCreated": "2024-03-15T10:22:31.123456Z",
        "Computer": "DC01.corp.local",
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
        "LogonType": 3,
        "AuthenticationPackageName": "NTLM",
        "IpAddress": "192.168.1.50",
        "IpPort": "49812",
        "LogonProcessName": "NtLmSsp",
        "SubjectUserSid": "S-1-5-18",
        "TargetUserSid": "S-1-5-21-1004336348-1177238915-682003330-1105",
    }


@pytest.fixture
def raw_event_4625():
    """Evento 4625 (logon fallido) con campos minimos."""
    return {
        "EventID": 4625,
        "TimeCreated": "2024-03-15T10:23:05.000000Z",
        "Computer": "DC01.corp.local",
        "TargetUserName": "admin",
        "LogonType": 3,
        "AuthenticationPackageName": "NTLM",
        "IpAddress": "10.0.0.7",
        "Status": "0xC000006D",
    }


def test_normalize_4624_valid(raw_event_4624):
    normalizer = EventNormalizer()
    result = normalizer.normalize(raw_event_4624)
    assert isinstance(result, WindowsEvent)
    assert result.event_id == 4624
    assert result.logon_type == 3


def test_normalize_sets_auth_package(raw_event_4624):
    normalizer = EventNormalizer()
    result = normalizer.normalize(raw_event_4624)
    assert result.auth_package == "NTLM"
    assert result.source_ip == "192.168.1.50"


def test_normalize_all_skips_invalid(raw_event_4624):
    normalizer = EventNormalizer()
    results = normalizer.normalize_all([raw_event_4624, {}])
    assert len(results) == 1
    assert results[0].event_id == 4624


def test_normalize_missing_optional_fields():
    raw = {
        "EventID": 4624,
        "TimeCreated": "2024-03-15T10:22:31.000000Z",
    }
    normalizer = EventNormalizer()
    result = normalizer.normalize(raw)
    assert result.event_id == 4624
    assert result.user_name is None
    assert result.source_ip is None
    assert result.auth_package is None
    assert result.logon_type is None
