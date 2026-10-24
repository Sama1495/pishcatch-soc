# Instrumentación de tiempos

Esta nota describe qué se mide hoy, dónde queda guardado y qué sigue pendiente. Ninguna cifra de tiempo ahorrado se calcula aquí. El campo opcional de minutos manuales en la pantalla de inicio es un dato que escribe la persona; en esta auditoría estaba vacío.

## Tiempo de análisis

El orquestador toma `time.perf_counter()` al entrar en `TriageOrchestrator.analyze` y guarda la diferencia en `incidents.processing_time_ms`.

- Código: `backend/app/agent/orchestrator.py`
- Columna: `backend/app/db/models.py` (`processing_time_ms`)
- Respuesta de `POST /api/v1/incidents` y del detalle del caso
- Auditoría `analysis_completed`, campo `processing_time_ms`
- Log `analysis_completed ... duration_ms=`
- Promedio: `GET /api/v1/metrics`, campo `average_processing_time_ms`
- Cada paso del timeline guarda `started_at`, `finished_at` y `duration_ms` en `operation_steps`

Ese intervalo cubre parseo, reglas, reputación, correlación, etiqueta, explicación y brief. No incluye el tiempo de subir el archivo por HTTP ni la lectura humana.

En la corrida viva del 2026-10-24 contra `http://127.0.0.1:8741`, con reputación y explicador apagados, el primer caso (`samples/clearly_phishing.eml`) guardó `processing_time_ms` 57 y la pared del cliente fue 93.7 ms. Los casos siguientes de esa misma serie quedaron entre 2 y 4 ms de procesamiento. El detalle por archivo está en `docs/alaris-readiness-audit.md`.

Al cerrar esa serie más una repetición de `synthetic_javascript_url.eml`, `GET /api/v1/metrics` devolvió:

- `case_count`: 12
- `average_processing_time_ms`: 9.0

Ese promedio es de esa base local (`sqlite:////tmp/phishcatch-audit.db`). No es un objetivo de servicio.

## Tiempo de revisión humana

Al terminar el análisis, el paso `awaiting_human_decision` queda en `waiting` con `started_at` igual al fin del análisis. Cuando una persona cierra esa espera, `complete_step` escribe `finished_at` y `duration_ms`.

Desde esta auditoría, ese `duration_ms` también se copia al evento de auditoría como `human_review_ms` y entra en el promedio de métricas.

| Escritura | Paso que se cierra | Evento |
| --- | --- | --- |
| `POST .../actions/response` | `awaiting_human_decision` | `action_response` |
| `POST .../actions/quarantine` cuando la política ofreció cuarentena | `awaiting_human_decision` | `quarantine_simulated` |
| `POST .../decisions` | `awaiting_human_decision` | `analyst_decision` |
| `POST .../feedback` | `human_decision` | `verdict_feedback` |

El promedio `average_human_review_ms` usa solo los pasos `awaiting_human_decision` con estado `done`. Un veredicto de “el agente acertó / se equivocó” no cierra esa espera y no entra en el promedio. Su propio `human_review_ms` queda en el evento `verdict_feedback`.

Código:

- `backend/app/agent/orchestrator.py` (`_human_review_ms`)
- `backend/app/services/steps.py`
- `backend/app/db/repository.py` (`metrics_snapshot`)
- `GET /api/v1/metrics`: `completed_human_reviews`, `average_human_review_ms`
- La home muestra ese promedio. Si `completed_human_reviews` es 0, el texto dice que todavía no hay una decisión y que eso no es un ahorro de tiempo.

### Qué incluye el número

`human_review_ms` es el reloj de pared desde que terminó el análisis hasta la escritura de la decisión. Incluye la espera en cola. No es un cronómetro de lectura activa. No resta un baseline manual. No debe presentarse como tiempo eliminado.

### Medición de esta auditoría

Una aprobación inmediata por API del caso `clearly_phishing.eml`, en la base viva, dejó:

- `POST /api/v1/incidents/{id}/actions/response` en 17.6 ms de pared
- auditoría `action_response.detail.human_review_ms`: 144
- `authorization`: `human_decision`
- `external_effect`: `none`
- después, `completed_human_reviews`: 1 y `average_human_review_ms`: 144.0

Esa persona no leyó el caso: fue una llamada `curl` justo después del análisis. 144 ms es la espera de esa llamada, no una revisión de analista.

El campo “Minutes this takes you by hand” sigue en `localStorage` (`phishcatch.manualMinutes`). Esta auditoría no escribió ningún valor. El ahorro frente a un baseline manual queda pendiente de medición.

## Qué no está instrumentado

- Tiempo de lectura activa (abrir el caso y decidir), separado de la espera en cola.
- Tiempo ahorrado frente a un analista.
- Exactitud del índice de confianza. Ese índice no es una medición. La exactitud del ruleset, si se vuelve a correr, sale de `python -m app.evaluate` y de `docs/evaluation.md`.
