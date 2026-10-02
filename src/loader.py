import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

import orjson
from Evtx.Evtx import Evtx

logger = logging.getLogger(__name__)

# Namespace XML habitual en los eventos exportados por Windows Event Log
_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


class EvtxLoader:
    """Carga eventos de Windows Security desde ficheros .evtx, .json o .ndjson.

    Devuelve una lista de diccionarios normalizados mínimamente, listos para
    ser procesados por la capa de normalización (EventNormalizer).
    """

    EXTENSIONES_SOPORTADAS = {".evtx", ".json", ".ndjson"}

    def __init__(self, path: str | Path) -> None:
        # Normalizamos siempre a Path para trabajar con métodos útiles
        self.path = Path(path)

    def load(self) -> list[dict]:
        """Carga el fichero y devuelve la lista de eventos como dicts."""
        if not self.path.exists():
            raise FileNotFoundError(f"No existe el fichero: {self.path}")

        ext = self.path.suffix.lower()
        if ext not in self.EXTENSIONES_SOPORTADAS:
            raise ValueError(
                f"Extensión no soportada: {ext}. "
                f"Use una de: {sorted(self.EXTENSIONES_SOPORTADAS)}"
            )

        if ext == ".evtx":
            eventos = self._load_evtx()
        elif ext == ".ndjson":
            eventos = self._load_ndjson()
        else:
            eventos = self._load_json()

        logger.info("Cargados %d eventos desde %s", len(eventos), self.path)
        return eventos

    def _load_evtx(self) -> list[dict]:
        """Itera los registros binarios .evtx y extrae los campos esenciales."""
        eventos: list[dict] = []
        with Evtx(str(self.path)) as log:
            for record in log.records():
                try:
                    root = ET.fromstring(record.xml())
                except ET.ParseError as exc:
                    logger.warning("XML inválido en record %s: %s", record.record_num(), exc)
                    continue

                system = root.find(f"{{{_EVTX_NS}}}System")
                if system is None:
                    continue

                event_id_el = system.find(f"{{{_EVTX_NS}}}EventID")
                time_el = system.find(f"{{{_EVTX_NS}}}TimeCreated")
                computer_el = system.find(f"{{{_EVTX_NS}}}Computer")
                channel_el = system.find(f"{{{_EVTX_NS}}}Channel")
                provider_el = system.find(f"{{{_EVTX_NS}}}Provider")

                raw_data: dict = {}
                event_data = root.find(f"{{{_EVTX_NS}}}EventData")
                if event_data is not None:
                    for data in event_data.findall(f"{{{_EVTX_NS}}}Data"):
                        nombre = data.get("Name")
                        if nombre:
                            raw_data[nombre] = (data.text or "").strip()

                eventos.append(
                    {
                        "event_id": int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0,
                        "timestamp": time_el.get("SystemTime") if time_el is not None else None,
                        "computer": computer_el.text if computer_el is not None else None,
                        "channel": channel_el.text if channel_el is not None else None,
                        "provider": provider_el.get("Name") if provider_el is not None else None,
                        "raw_data": raw_data,
                    }
                )
        return eventos

    def _load_json(self) -> list[dict]:
        """Carga un fichero JSON completo que contenga una lista de eventos."""
        contenido = self.path.read_bytes()
        datos = orjson.loads(contenido)
        if isinstance(datos, dict):
            # Permitimos envoltorios tipo {"events": [...]}
            datos = datos.get("events", [datos])
        if not isinstance(datos, list):
            raise ValueError("El fichero JSON debe contener una lista de eventos")
        return [self._normalizar_entrada(e) for e in datos]

    def _load_ndjson(self) -> list[dict]:
        """Carga un fichero NDJSON (un evento JSON por línea)."""
        eventos: list[dict] = []
        with self.path.open("rb") as fh:
            for num_linea, linea in enumerate(fh, start=1):
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    eventos.append(self._normalizar_entrada(orjson.loads(linea)))
                except orjson.JSONDecodeError as exc:
                    logger.warning("Línea %d no es JSON válido: %s", num_linea, exc)
        return eventos

    @staticmethod
    def _normalizar_entrada(evento: dict) -> dict:
        """Asegura que cada evento JSON tenga las claves mínimas esperadas."""
        return {
            "event_id": int(evento.get("event_id", evento.get("EventID", 0)) or 0),
            "timestamp": evento.get("timestamp") or evento.get("@timestamp"),
            "computer": evento.get("computer") or evento.get("host"),
            "channel": evento.get("channel"),
            "provider": evento.get("provider"),
            "raw_data": evento.get("raw_data") or evento.get("EventData") or {},
        }
