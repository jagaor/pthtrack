import logging
from typing import List, Dict, Any
from elasticsearch import Elasticsearch, helpers

logger = logging.getLogger(__name__)


class ElasticExporter:
    """Exportador a Elasticsearch usando elasticsearch-py v8."""

    def __init__(self, url: str, index: str):
        """
        Inicializa el cliente de Elasticsearch.

        Args:
            url: URL del clúster (ej. http://localhost:9200).
            index: Nombre base del índice para eventos ECS.
        """
        self.url = url
        self.index = index
        self.client = Elasticsearch(url)

    def test_connection(self) -> bool:
        """Comprueba si el clúster responde. Devuelve True si está disponible."""
        try:
            return self.client.ping()
        except Exception as exc:
            logger.error("Error al conectar con Elasticsearch: %s", exc)
            return False

    def bulk_index(
        self, ecs_events: List[Dict[str, Any]], alerts: List[Any]
    ) -> Dict[str, Any]:
        """
        Indexa eventos ECS y alertas en bloque.

        Args:
            ecs_events: Lista de diccionarios en formato ECS.
            alerts: Lista de objetos Alert (con atributos id, severity, etc.).

        Returns:
            Diccionario con indexed_events, indexed_alerts y errores.

        Raises:
            ConnectionError: Si falla la conexión con Elasticsearch.
        """
        if not self.test_connection():
            raise ConnectionError(
                f"No se pudo conectar a Elasticsearch en {self.url}. "
                "Verifica la URL y que el servicio esté en ejecución."
            )

        actions = []
        # Acciones para eventos ECS
        for event in ecs_events:
            actions.append({
                "_index": self.index,
                "_source": event,
            })
        # Acciones para alertas
        alerts_index = f"{self.index}-alerts"
        for alert in alerts:
            actions.append({
                "_index": alerts_index,
                "_source": alert.model_dump() if hasattr(alert, "model_dump") else alert,
            })

        if not actions:
            return {"indexed_events": 0, "indexed_alerts": 0, "errors": []}

        try:
            success, errors = helpers.bulk(
                self.client,
                actions,
                stats_only=False,
                raise_on_error=False,
            )
        except Exception as exc:
            raise ConnectionError(
                f"Error durante la indexación en Elasticsearch: {exc}"
            ) from exc

        indexed_events = len(ecs_events)
        indexed_alerts = len(alerts)
        # Si helpers.bulk devuelve errores, ajustamos contadores
        if errors:
            logger.warning("Errores durante bulk index: %s", errors)
            # Los errores pueden afectar a eventos o alertas; se reportan sin desglose exacto
            indexed_events = success if success <= len(ecs_events) else len(ecs_events)
            indexed_alerts = max(0, success - indexed_events)

        return {
            "indexed_events": indexed_events,
            "indexed_alerts": indexed_alerts,
            "errors": errors,
        }
