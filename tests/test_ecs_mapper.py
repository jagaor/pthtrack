import pytest
from datetime import datetime, UTC

from src.normalizer import WindowsEvent
from src.ecs_mapper import ECSMapper


@pytest.fixture
def mapper():
    # Instancia reutilizable del mapeador ECS para todos los tests
    return ECSMapper()


@pytest.fixture
def win_event_4624():
    # Evento 4624 típico de logon de red con paquete NTLM (escenario PthTrack)
    return WindowsEvent(
        event_id=4624,
        timestamp=datetime.now(UTC),
        computer="CORP-WS-01",
        target_user_name="alice",
        logon_type=3,
        auth_package="NTLM",
        ip_address="10.0.0.5",
        ip_port=445,
        subject_user_sid="S-1-5-21-xxx",
        raw={},
    )


def test_map_event_returns_dict(mapper, win_event_4624):
    # El resultado del mapeo debe ser un diccionario serializable
    event = mapper.map_event(win_event_4624)
    assert isinstance(event, dict)


def test_ecs_timestamp_format(mapper, win_event_4624):
    # @timestamp debe ser string ISO8601 con sufijo Z (UTC)
    event = mapper.map_event(win_event_4624)
    assert isinstance(event["@timestamp"], str)
    assert event["@timestamp"].endswith("Z")


def test_event_code_is_string(mapper, win_event_4624):
    # ECS exige event.code como string, no como entero
    event = mapper.map_event(win_event_4624)
    assert event["event"]["code"] == "4624"


def test_event_action_logon(mapper, win_event_4624):
    # El EventID 4624 se traduce a la acción semántica 'logon'
    event = mapper.map_event(win_event_4624)
    assert event["event"]["action"] == "logon"


def test_host_name_mapped(mapper, win_event_4624):
    # El nombre del equipo se mapea a host.name
    event = mapper.map_event(win_event_4624)
    assert event["host"]["name"] == "CORP-WS-01"


def test_winlog_logon_type(mapper, win_event_4624):
    # El tipo de logon se preserva en winlog.logon.type como entero
    event = mapper.map_event(win_event_4624)
    assert event["winlog"]["logon"]["type"] == 3


def test_ecs_version_present(mapper, win_event_4624):
    # Todo documento ECS debe declarar la versión del esquema
    event = mapper.map_event(win_event_4624)
    assert event["ecs"]["version"] == "8.11.0"


def test_tags_contain_pthtrack(mapper, win_event_4624):
    # Todos los eventos llevan la etiqueta de origen pthtrack
    event = mapper.map_event(win_event_4624)
    assert "pthtrack" in event["tags"]
