import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from loader import EvtxLoader
from normalizer import EventNormalizer
from ecs_mapper import ECSMapper
from detector import PthDetector

# Almacenes en memoria compartidos por los endpoints
alerts_store: list[dict[str, Any]] = []
events_store: list[dict[str, Any]] = []

app = FastAPI(title="PthTrack API", version="1.0.0")


class IngestRequest(BaseModel):
    file_path: str = Field(..., description="Ruta al fichero .evtx o JSON de eventos")
    detect_pth: bool = Field(True, description="Activar deteccion Pass-the-Hash")


class IngestResponse(BaseModel):
    events_processed: int
    alerts_found: int


class HealthResponse(BaseModel):
    status: str
    version: str


class AlertsPage(BaseModel):
    total: int
    page: int
    size: int
    alerts: list[dict[str, Any]]


def _run_pipeline(file_path: str, detect_pth: bool) -> tuple[list[dict], list[dict]]:
    """Ejecuta ingesta, normalizacion, mapeo ECS y deteccion."""
    loader = EvtxLoader(file_path)
    normalizer = EventNormalizer()
    mapper = ECSMapper()
    detector = PthDetector()

    normalized: list[dict[str, Any]] = []
    for raw in loader.iter_events():
        model = normalizer.normalize(raw)
        if model is None:
            continue
        normalized.append(mapper.to_ecs(model))

    alerts: list[dict[str, Any]] = []
    if detect_pth:
        alerts = detector.detect(normalized)
    return normalized, alerts


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version="1.0.0")


@app.get("/alerts", response_model=AlertsPage)
def list_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
) -> AlertsPage:
    total = len(alerts_store)
    start = (page - 1) * size
    end = start + size
    return AlertsPage(total=total, page=page, size=size, alerts=alerts_store[start:end])


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int) -> dict[str, Any]:
    if alert_id < 0 or alert_id >= len(alerts_store):
        raise HTTPException(status_code=404, detail="Alerta no encontrada")
    return alerts_store[alert_id]


@app.post("/ingest", response_model=IngestResponse)
def ingest(req: IngestRequest) -> IngestResponse:
    if not os.path.isfile(req.file_path):
        raise HTTPException(status_code=400, detail="file_path no existe")
    events, alerts = _run_pipeline(req.file_path, req.detect_pth)
    events_store.extend(events)
    alerts_store.extend(alerts)
    return IngestResponse(events_processed=len(events), alerts_found=len(alerts))


# Precarga opcional desde variable de entorno al importar el modulo
_preload = os.getenv("PTHTRACK_PRELOAD")
if _preload and os.path.isfile(_preload):
    try:
        _events, _alerts = _run_pipeline(_preload, True)
        events_store.extend(_events)
        alerts_store.extend(_alerts)
    except Exception:
        # La precarga no debe impedir el arranque de la API
        pass
