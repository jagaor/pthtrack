"""Módulo de normalización de eventos de Windows Security.

Transforma los diccionarios crudos emitidos por EvtxLoader en modelos
Pydantic v2 validados (WindowsEvent), listos para el mapeo a ECS.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


class WindowsEvent(BaseModel):
    """Representación normalizada de un evento de Windows Security."""

    model_config = ConfigDict(extra="allow")

    event_id: int
    timestamp: datetime
    computer: str
    provider: str
    channel: str
    subject_user_name: Optional[str] = None
    subject_domain: Optional[str] = None
    subject_logon_id: Optional[str] = None
    target_user_name: Optional[str] = None
    target_domain: Optional[str] = None
    target_logon_id: Optional[str] = None
    logon_type: Optional[int] = None
    auth_package: Optional[str] = None
    workstation_name: Optional[str] = None
    ip_address: Optional[str] = None
    ip_port: Optional[int] = None
    subject_user_sid: Optional[str] = None
    privilege_list: Optional[str] = None
    raw: dict = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _parse_timestamp(cls, value: Any) -> Any:
        """Acepta datetime o string ISO y garantiza tz-aware en UTC."""
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, datetime) and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class EventNormalizer:
    """Convierte diccionarios crudos de EvtxLoader en WindowsEvent."""

    # Mapeo directo EventData -> campo del modelo
    _FIELD_MAP = {
        "SubjectUserName": "subject_user_name",
        "SubjectDomainName": "subject_domain",
        "SubjectLogonId": "subject_logon_id",
        "TargetUserName": "target_user_name",
        "TargetDomainName": "target_domain",
        "TargetLogonId": "target_logon_id",
        "LogonType": "logon_type",
        "AuthenticationPackageName": "auth_package",
        "WorkstationName": "workstation_name",
        "IpAddress": "ip_address",
        "IpPort": "ip_port",
        "SubjectUserSid": "subject_user_sid",
        "PrivilegeList": "privilege_list",
    }

    def normalize(self, raw: dict) -> WindowsEvent:
        """Normaliza un único evento crudo. Lanza ValidationError si es inválido."""
        event_data = raw.get("EventData", raw.get("event_data", {})) or {}
        system = raw.get("System", raw.get("system", {})) or {}

        payload: dict[str, Any] = {
            "event_id": int(system.get("EventID", raw.get("event_id", 0))),
            "timestamp": system.get("TimeCreated", raw.get("timestamp")),
            "computer": system.get("Computer", raw.get("computer", "")),
            "provider": system.get("Provider", raw.get("provider", "")),
            "channel": system.get("Channel", raw.get("channel", "Security")),
            "raw": raw,
        }

        for src_key, dst_key in self._FIELD_MAP.items():
            value = event_data.get(src_key)
            if value is not None and value != "-":
                payload[dst_key] = value

        # Conversión explícita de tipos numéricos cuando llegan como string
        if "logon_type" in payload:
            payload["logon_type"] = int(payload["logon_type"])
        if "ip_port" in payload:
            payload["ip_port"] = int(payload["ip_port"])

        return WindowsEvent(**payload)

    def normalize_all(self, raws: list[dict]) -> list[WindowsEvent]:
        """Normaliza una lista completa, descartando eventos inválidos."""
        validos: list[WindowsEvent] = []
        for idx, raw in enumerate(raws):
            try:
                validos.append(self.normalize(raw))
            except (ValidationError, ValueError, TypeError) as exc:
                logger.warning("Evento descartado en índice %d: %s", idx, exc)
        return validos
