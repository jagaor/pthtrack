#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Punto de entrada CLI de PthTrack.

Orquesta el pipeline completo: carga de eventos .evtx/JSON, normalización
Pydantic v2, mapeo a Elastic Common Schema, detección Pass-the-Hash,
exportación a fichero o a Elasticsearch y arranque opcional de la API.

Autor: Javier Garrido Ortiz
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import orjson
from rich.console import Console
from rich.table import Table

from src.loader import EvtxLoader
from src.normalizer import EventNormalizer
from src.ecs_mapper import ECSMapper
from src.detector import PthDetector
from src.exporter import ElasticExporter

console = Console()
logger = logging.getLogger("pthtrack")


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos de la CLI."""
    p = argparse.ArgumentParser(
        prog="pthtrack",
        description="Convierte logs Windows Security Event a ECS y detecta Pass-the-Hash.",
    )
    p.add_argument("--input", required=True, help="Ruta a fichero .evtx o JSON de eventos.")
    p.add_argument("--output", default=None, help="Ruta de salida (por defecto STDOUT).")
    p.add_argument("--format", choices=("json", "ndjson"), default="json", help="Formato de salida.")
    p.add_argument("--detect-pth", action="store_true", help="Activa el motor de detección Pass-the-Hash.")
    p.add_argument("--elastic-url", default=None, help="URL de Elasticsearch para indexar resultados.")
    p.add_argument("--elastic-index", default="pthtrack-logs", help="Nombre del índice en Elasticsearch.")
    p.add_argument("--serve", action="store_true", help="Arranca la API FastAPI en el puerto 8000.")
    p.add_argument("--verbose", action="store_true", help="Activa logs de depuración.")
    return p


def serialize(events: list[dict], alerts: list, fmt: str) -> bytes:
    """Serializa eventos y alertas con orjson según el formato pedido."""
    payload = {"events": events, "alerts": [a.model_dump(mode="json") for a in alerts]}
    if fmt == "ndjson":
        lines = [orjson.dumps(ev) for ev in events]
        lines += [orjson.dumps(a.model_dump(mode="json")) for a in alerts]
        return b"\n".join(lines) + b"\n"
    return orjson.dumps(payload, option=orjson.OPT_INDENT_2)


def write_output(data: bytes, output: str | None) -> None:
    """Escribe la salida en fichero o en STDOUT."""
    if output:
        Path(output).write_bytes(data)
        console.print(f"[green]Salida escrita en[/green] {output}")
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def print_summary(n_events: int, n_alerts: int, n_critical: int) -> None:
    """Muestra un panel resumen con rich."""
    table = Table(title="PthTrack - Resumen de ejecución")
    table.add_column("Métrica", style="cyan")
    table.add_column("Valor", style="magenta")
    table.add_row("Eventos ECS generados", str(n_events))
    table.add_row("Alertas Pass-the-Hash", str(n_alerts))
    table.add_row("Alertas CRITICAL", str(n_critical))
    console.print(table)


def run(args: argparse.Namespace) -> int:
    """Ejecuta el pipeline completo según los argumentos recibidos."""
    # 1) Carga de eventos crudos desde .evtx o JSON.
    loader = EvtxLoader(args.input)
    raw_events = loader.load()
    logger.debug("Eventos crudos cargados: %d", len(raw_events))

    # 2) Normalización a modelos Pydantic v2.
    normalizer = EventNormalizer()
    normalized = normalizer.normalize_all(raw_events)

    # 3) Mapeo a Elastic Common Schema v8.
    mapper = ECSMapper()
    ecs_events = mapper.map_all(normalized)

    # 4) Detección opcional de Pass-the-Hash (MITRE T1550.002).
    alerts = []
    if args.detect_pth:
        detector = PthDetector()
        alerts = detector.analyze(ecs_events)

    # 5) Serialización y escritura de resultados.
    data = serialize(ecs_events, alerts, args.format)
    write_output(data, args.output)

    # 6) Indexado opcional en Elasticsearch.
    if args.elastic_url:
        exporter = ElasticExporter(args.elastic_url, args.elastic_index)
        exporter.bulk_index(ecs_events, alerts)
        console.print(f"[green]Indexados en[/green] {args.elastic_index}")

    # 7) Arranque opcional de la API FastAPI.
    if args.serve:
        import uvicorn
        uvicorn.run("src.api:app", host="0.0.0.0", port=8000)

    n_critical = sum(1 for a in alerts if getattr(a, "severity", "") == "CRITICAL")
    print_summary(len(ecs_events), len(alerts), n_critical)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Función principal de la CLI."""
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        return run(args)
    except Exception as exc:  # noqa: BLE001 - reporte final al usuario
        console.print(f"[red]Error:[/red] {exc}")
        logger.exception("Fallo en el pipeline")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
