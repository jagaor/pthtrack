"""Módulo ECSMapper: transforma eventos Windows normalizados al esquema Elastic Common Schema v8.

Este módulo no accede a red ni a disco. Recibe instancias de WindowsEvent
(modelo Pydantic definido en normalizer.py) y devuelve diccionarios planos
listos para ser serializados con orjson o indexados en Elasticsearch.
"""

from __future__ import annotations

from typing import Any

from src.normalizer import WindowsEvent


# Versión de ECS contra la que se construye la salida.
ECS_VERSION = "8.11.0"

# Mapeo EventID -> event.action según la convención de PthTrack.
# Cubre los eventos relevantes para T1550.002 (Pass-the-Hash).
_EVENT_ACTIONS: dict[int, str] = {
    4624: "logon",
    4625: "logon-failed",
    4648: "explicit-credentials-logon",
    4672: "special-logon",
    4768: "kerberos-tgt-request",
    4769: "kerberos-service-ticket",
}

# Mapeo EventID -> event.type (start/end/info) según ECS.
# Los logons exitosos marcan 'start', los fallos 'end', el resto 'info'.
_EVENT_TYPES: dict[int, str] = {
    4624: "start",
    4625: "end",
    4648: "info",
    4672: "info",
    4768: "start",
    4769: "start",
}


class ECSMapper:
    """Traductor sin estado de WindowsEvent a documentos ECS v8.

    Todos los métodos son de instancia para permitir futuras extensiones
    (por ejemplo, inyectar un mapeador de hostname personalizado), pero no
    mantienen estado entre llamadas.
    """

    def map_event(self, event: WindowsEvent) -> dict[str, Any]:
        """Construye el documento ECS v8 completo para un único evento."""
        event_id = int(event.event_id)

        # @timestamp en ISO8601 UTC, tal y como lo espera Elasticsearch.
        doc: dict[str, Any] = {
            "@timestamp": event.timestamp.isoformat(),
            "ecs.version": ECS_VERSION,
        }

        # Bloque event.*: identifica el tipo de evento Windows en términos ECS.
        doc["event.code"] = str(event_id)
        doc["event.action"] = _EVENT_ACTIONS.get(event_id, "unknown")
        doc["event.category"] = ["authentication"]
        doc["event.type"] = [_EVENT_TYPES.get(event_id, "info")]
        doc["event.dataset"] = "windows.security"

        # host.name: nombre del equipo que generó el evento (Computer).
        if event.computer:
            doc["host.name"] = event.computer

        # user.*: identidad objetivo del logon (TargetUserName / TargetDomainName).
        if event.target_user_name:
            doc["user.name"] = event.target_user_name
        if event.target_domain:
            doc["user.domain"] = event.target_domain

        # source.*: origen de red de la autenticación (IpAddress / IpPort).
        if event.ip_address:
            doc["source.ip"] = event.ip_address
        if event.ip_port is not None:
            doc["source.port"] = int(event.ip_port)

        # winlog.logon.*: tipo de logon y paquete de autenticación.
        # Son los campos clave para detectar Pass-the-Hash (LogonType=3 + NTLM).
        if event.logon_type is not None:
            doc["winlog.logon.type"] = str(event.logon_type)
        if event.auth_package:
            doc["winlog.logon.auth_package"] = event.auth_package

        # winlog.subject.*: identidad del sujeto que ejecuta la acción.
        if event.subject_user_name:
            doc["winlog.subject.name"] = event.subject_user_name
        if event.subject_user_sid:
            doc["winlog.subject.sid"] = event.subject_user_sid

        # Etiqueta fija para filtrar todos los documentos de PthTrack.
        doc["tags"] = ["pthtrack"]

        return doc

    def map_all(self, events: list[WindowsEvent]) -> list[dict[str, Any]]:
        """Aplica map_event a una lista completa de eventos."""
        return [self.map_event(ev) for ev in events]
