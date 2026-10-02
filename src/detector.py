"""Módulo de detección de Pass-the-Hash (PthDetector).

Implementa un motor de reglas basado en patrones documentados en MITRE ATT&CK
T1550.002 (Use Alternate Authentication Material: Pass the Hash). Cada regla
inspecciona un evento ECS ya normalizado y, si se cumple el patrón, emite una
alerta con severidad y referencia MITRE.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Alert:
    """Alerta generada por el detector."""

    rule_name: str
    severity: str  # HIGH | CRITICAL
    event_code: str
    timestamp: str
    host: str
    user: str
    logon_type: Optional[int] = None
    auth_package: Optional[str] = None
    workstation: Optional[str] = None
    mitre_technique: str = "T1550.002"
    description: str = ""


class PthDetector:
    """Detector de Pass-the-Hash basado en reglas sobre eventos ECS."""

    def _get(self, event: dict, path: str, default=None):
        """Accede a un campo anidado tipo 'winlog.logon.type'."""
        current = event
        for key in path.split("."):
            if not isinstance(current, dict):
                return default
            current = current.get(key)
            if current is None:
                return default
        return current

    def _rule_ntlm_network_logon(self, event: dict) -> Optional[Alert]:
        """Regla NTLM_LOGON_4624_TYPE3.

        Detecta logon de red (LogonType=3) con paquete NTLM en EventID 4624.
        Es el patrón clásico de Pass-the-Hash: el atacante reutiliza el hash
        NTLM para autenticarse sin conocer la contraseña en claro.
        """
        if self._get(event, "event.code") != "4624":
            return None
        if self._get(event, "winlog.logon.type") != 3:
            return None
        if self._get(event, "winlog.logon.auth_package") != "NTLM":
            return None
        user = self._get(event, "user.name")
        if not user or user.startswith("$"):
            return None
        return Alert(
            rule_name="NTLM_LOGON_4624_TYPE3",
            severity="HIGH",
            event_code="4624",
            timestamp=self._get(event, "@timestamp", ""),
            host=self._get(event, "host.name", ""),
            user=user,
            logon_type=3,
            auth_package="NTLM",
            workstation=self._get(event, "winlog.event_data.WorkstationName"),
            description=(
                "Logon de red con paquete NTLM. Posible Pass-the-Hash "
                "reutilizando hash NTLM en lugar de credenciales Kerberos."
            ),
        )

    def _rule_anonymous_ntlm(self, event: dict) -> Optional[Alert]:
        """Regla ANON_LOGON_MISMATCH_4624.

        Detecta logon de red con usuario ANONYMOUS LOGON. En un entorno
        Windows sano este tipo de logon no debería ocurrir con LogonType=3;
        su presencia sugiere manipulación de tokens o intentos de pivote.
        """
        if self._get(event, "event.code") != "4624":
            return None
        if self._get(event, "winlog.logon.type") != 3:
            return None
        user = self._get(event, "user.name")
        if user not in ("ANONYMOUS LOGON", "ANONYMOUS"):
            return None
        return Alert(
            rule_name="ANON_LOGON_MISMATCH_4624",
            severity="CRITICAL",
            event_code="4624",
            timestamp=self._get(event, "@timestamp", ""),
            host=self._get(event, "host.name", ""),
            user=user,
            logon_type=3,
            auth_package=self._get(event, "winlog.logon.auth_package"),
            workstation=self._get(event, "winlog.event_data.WorkstationName"),
            description=(
                "Logon anónimo de red. Indica autenticación no identificada "
                "compatible con Pass-the-Hash o movimiento lateral anómalo."
            ),
        )

    def _rule_kerberos_fallback(self, event: dict) -> Optional[Alert]:
        """Regla KERBEROS_DISABLED_4625.

        Detecta fallo de autenticación (4625) usando NTLM. Cuando Kerberos
        está disponible, un fallo NTLM puede indicar que el atacante está
        forzando autenticación NTLM con hashes robados.
        """
        if self._get(event, "event.code") != "4625":
            return None
        if self._get(event, "winlog.logon.auth_package") != "NTLM":
            return None
        return Alert(
            rule_name="KERBEROS_DISABLED_4625",
            severity="HIGH",
            event_code="4625",
            timestamp=self._get(event, "@timestamp", ""),
            host=self._get(event, "host.name", ""),
            user=self._get(event, "user.name", ""),
            logon_type=self._get(event, "winlog.logon.type"),
            auth_package="NTLM",
            workstation=self._get(event, "winlog.event_data.WorkstationName"),
            description=(
                "Fallo de autenticación con NTLM. Posible intento de "
                "Pass-the-Hash con hash inválido o cuenta deshabilitada."
            ),
        )

    def _rule_explicit_creds_null_sid(self, event: dict) -> Optional[Alert]:
        """Regla SECLOGON_NULL_SID_4648.

        Detecta uso explícito de credenciales (4648) con SID nulo o nulo
        (S-1-0-0). Indica que el proceso no tiene identidad asociada, lo
        que sugiere suplantación de token o ejecución con credenciales
        inyectadas (Pass-the-Hash).
        """
        if self._get(event, "event.code") != "4648":
            return None
        sid = self._get(event, "winlog.subject.sid")
        if sid not in ("S-1-0-0", None, ""):
            return None
        return Alert(
            rule_name="SECLOGON_NULL_SID_4648",
            severity="CRITICAL",
            event_code="4648",
            timestamp=self._get(event, "@timestamp", ""),
            host=self._get(event, "host.name", ""),
            user=self._get(event, "user.name", ""),
            logon_type=self._get(event, "winlog.logon.type"),
            auth_package=self._get(event, "winlog.logon.auth_package"),
            workstation=self._get(event, "winlog.event_data.TargetInfo"),
            description=(
                "Uso explícito de credenciales con SID nulo. Fuerte "
                "indicador de suplantación de token o Pass-the-Hash."
            ),
        )

    def analyze(self, ecs_events: list[dict]) -> list[Alert]:
        """Aplica todas las reglas a la lista de eventos ECS y devuelve alertas."""
        alerts: list[Alert] = []
        rules = (
            self._rule_ntlm_network_logon,
            self._rule_anonymous_ntlm,
            self._rule_kerberos_fallback,
            self._rule_explicit_creds_null_sid,
        )
        for event in ecs_events:
            for rule in rules:
                alert = rule(event)
                if alert is not None:
                    alerts.append(alert)
        return alerts
