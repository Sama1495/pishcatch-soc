# Auditoría de preparación para Alaris Security

Fecha de la corrida: 2026-10-24. Máquina local, API en `127.0.0.1:8741`, interfaz en `127.0.0.1:8742`. Reputación y explicador apagados (`GET /health`: `reputation_enabled` false, `ai_enabled` false, `explainer_provider` `off`, `ruleset` `1.1.0`).

Esta auditoría no inventa métricas. Cada cifra de abajo sale de una corrida citada. La evaluación del corpus de 500 mensajes no se repitió: `data/corpora/` no estaba en la máquina. El panel sigue mostrando `backend/app/evaluation/latest.json` (generado `2026-10-24T18:20:26+00:00`).

Documentos ligados:

- Resultados de prueba y criterios: este archivo.
- Procedimiento de muestras: [alaris-evaluacion-muestras.md](alaris-evaluacion-muestras.md).
- Tiempos: [alaris-instrumentacion.md](alaris-instrumentacion.md).
- Guion: [alaris-demo-150s.md](alaris-demo-150s.md).

## Veredicto corto

El flujo sintético de extremo a extremo funciona y se puede enseñar en 150 segundos sin red. El puesto alto depende de no prometer ahorro de tiempo ni exactitud del índice, y de tener el corpus en el portátil si el jurado pide correo público en vivo. Sin ese directorio, los botones de corpus no aparecen. Las muestras del repositorio y el JSON de evaluación almacenado sí están.

## Resultados de pruebas

Comando, desde `backend/`, después de los cambios de esta auditoría:

```bash
.venv/bin/python -m pytest --override-ini="addopts=" -q -p no:warnings --tb=short
```

Resultado final: **78 passed in 2.47s**. Fallidas: 0. Omitidas: 0. No ejecutables de esta suite: 0.

| Archivo | Pasaron |
| --- | ---: |
| `tests/test_analyze_flow.py` | 9 |
| `tests/test_audit_readiness.py` | 10 |
| `tests/test_batch.py` | 2 |
| `tests/test_confidence.py` | 5 |
| `tests/test_gemini.py` | 4 |
| `tests/test_health.py` | 1 |
| `tests/test_integrations.py` | 6 |
| `tests/test_parser.py` | 6 |
| `tests/test_policy.py` | 3 |
| `tests/test_pretext.py` | 5 |
| `tests/test_robustness.py` | 5 |
| `tests/test_rules.py` | 9 |
| `tests/test_trust_loop.py` | 5 |
| `tests/test_upload_validation.py` | 8 |
| Total | 78 |

Nombres de `tests/test_audit_readiness.py`, añadidos para esta revisión. Todos pasaron:

- `test_prompt_injection_does_not_fabricate_a_safe_verdict`
- `test_contradictory_mail_stays_suspicious_and_not_cleared`
- `test_javascript_url_is_defanged_and_not_a_clearance`
- `test_sparse_mail_is_inconclusive`
- `test_not_email_and_zip_and_null_bytes_fail_closed`
- `test_risky_attachment_name_is_metadata_only`
- `test_explainer_and_reputation_outages_keep_the_label`
- `test_same_sender_after_a_suspicious_case_is_not_cleared`
- `test_quarantine_without_offer_is_audited_and_not_applied`
- `test_offered_quarantine_records_review_time_and_blocks_a_repeat`

El resto de la lista, también en verde, es la suite que ya estaba: flujo, lote, confianza, Gemini, salud, integraciones, parser, política, pretexto, robustez, reglas, bucle humano y validación de carga.

Otras comprobaciones:

| Comprobación | Resultado |
| --- | --- |
| `cd frontend && npm run build` (`tsc --noEmit` y Vite) | Terminó en 0. Artefacto `dist/` ignorado por git. |
| Suite unitaria o de integración del frontend | No existe script de test en `frontend/package.json`. No se pudo ejecutar. |
| `python -m app.evaluate` sobre el corpus | No se ejecutó. Falta `data/corpora/`. El JSON almacenado sí se sirvió por `GET /api/v1/evaluation`. |
| Llamada real a Gemini o a VirusTotal | No se hizo. No hay clave en el entorno de la auditoría. La degradación se probó con una excepción sintética y con las pruebas ya existentes de timeout, 429 y JSON inválido. |

## Corrida viva del flujo

Base vacía `sqlite:////tmp/phishcatch-audit.db`, subidas en este orden. Pared: reloj del cliente. Proc: `processing_time_ms` guardado.

| Archivo | HTTP | Pared ms | Proc ms | Etiqueta | Puntos | Índice | Banda | Acción |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- | --- |
| `samples/clearly_phishing.eml` | 201 | 93.7 | 57 | likely_malicious | 100 | 83 | high | simulate_quarantine |
| `samples/ambiguous.eml` | 201 | 13.9 | 4 | suspicious | 45 | 57 | medium | analyst_review |
| `samples/clearly_benign.eml` | 201 | 10.0 | 3 | inconclusive | 0 | 40 | medium | manual_investigation |
| `samples/no_signals.eml` | 201 | 10.7 | 2 | inconclusive | 0 | 38 | low | manual_investigation |
| `samples/malformed.eml` | 400 | 2.2 | — | invalid_content | — | — | — | — |
| `samples/empty.eml` | 400 | 1.7 | — | empty_file | — | — | — | — |
| `samples/certification_lure_clean_auth.eml` | 201 | 9.8 | 3 | likely_malicious | 100 | 76 | high | simulate_quarantine |
| `samples/certification_benign.eml` | 201 | 11.4 | 4 | inconclusive | 0 | 40 | medium | manual_investigation |
| `samples/audit/synthetic_prompt_injection.eml` | 201 | 10.5 | 3 | suspicious | 20 | 51 | medium | analyst_review |
| `samples/audit/synthetic_contradictory.eml` | 201 | 10.1 | 2 | suspicious | 25 | 49 | medium | analyst_review |
| `samples/audit/synthetic_javascript_url.eml` | 201 | 9.4 | 2 | suspicious | 50 | 63 | medium | analyst_review |
| `samples/audit/synthetic_sparse.eml` | 201 | 9.0 | 2 | suspicious | 10 | 47 | medium | analyst_review |
| `samples/audit/synthetic_not_email.eml` | 400 | 1.9 | — | invalid_content | — | — | — | — |
| `samples/audit/synthetic_risky_name.eml` | 201 | 11.9 | 3 | suspicious | 45 | 61 | medium | analyst_review |

Explicador `disabled` y reputación `disabled` en todos los 201 de esta serie. `GET /health` siguió respondiendo después de los 400.

`synthetic_sparse.eml` salió `suspicious` en esta serie porque iba después de `synthetic_prompt_injection.eml` y comparten el buzón `audit-bot@example`. La evidencia fue `related_indicator_in_prior_case`. En una base nueva, el mismo archivo queda `inconclusive`, puntos 0, índice 38, banda low, acción `manual_investigation`, evidencia `no_suspicious_signals` (TestClient, procesamiento 20 ms por ser la primera petición de ese proceso). Un seguimiento sintético del mismo buzón, sin enlaces, quedó `suspicious`, puntos 10, índice 47, una sola regla de correlación. La prueba que lo fija es `test_same_sender_after_a_suspicious_case_is_not_cleared`.

`synthetic_javascript_url.eml` sumó 50 en la serie viva (40 del esquema más 10 de correlación). Tras el arreglo del defang, una repetición guardó `javascript[colon]alert(1)`. El original sigue siendo `javascript:alert(1)`. La ficha lo muestra en un `<code>`, no en un enlace.

Aprobación del phishing de esa serie:

- `POST .../actions/response` con `approve`: HTTP 200 en 17.6 ms, `simulated` true, `external_effect` `none`, estado `quarantine_simulated`.
- Auditoría `action_response`: `authorization` `human_decision`, `human_review_ms` 144.
- Intento posterior de `POST .../actions/quarantine`: HTTP 409.

Cuarentena de `synthetic_sparse.eml`, cuya acción ofrecida era `analyst_review`: HTTP 403 en 9.8 ms, código `action_not_authorized`. El caso siguió `open`. El evento `action_denied` tiene `reason_code` `action_not_offered` y `external_effect` `none`.

`GET /api/v1/metrics` al cerrar la serie más la repetición del javascript (12 casos, 1 decisión):

- `average_processing_time_ms`: 9.0
- `completed_human_reviews`: 1
- `average_human_review_ms`: 144.0
- `feedback_total`: 0
- `raw_agreement_rate`: null
- `shrunk_agreement_percent`: 50

El 50 es el prior de la fórmula con cero veredictos. El propio disclaimer de la API dice que no es una exactitud medida.

`GET /api/v1/demo-pack` listó siete muestras del repositorio. No listó `corpus_phish_1`, `corpus_phish_2`, `corpus_ham_1` ni `corpus_ham_2`: esos `.eml` no están en `samples/demo-pack/`.

## Interfaz

Chrome headless 156, `prefers-reduced-motion: reduce`, contra la ficha del phishing ya aprobado y contra la home. Texto leído del DOM:

- “high confidence index” y “83 index”.
- El disclaimer de que el índice no es una exactitud medida ni una probabilidad.
- FishBot: “Confidence index 83 (high). It says how strongly this ruleset supports its own verdict. It is not a measured accuracy.”
- “Quarantine was simulated. No mailbox or message was modified.”
- “Auto-execute: off.”
- Home: promedio de análisis 9 ms; revisión humana “144 ms across 1 decisions”; acuerdo “No verdict feedback yet”; prior 50 % con el disclaimer.
- Con el corpus ausente, el texto del pack dice que los botones de corpus están ocultos y que los visibles son sintéticos.

## 1. Viabilidad

El flujo pedido está implementado y se recorrió.

| Paso | Evidencia |
| --- | --- |
| Carga `.eml` | `POST /api/v1/incidents`. Validación en `backend/app/api/uploads.py` y `tests/test_upload_validation.py`. |
| Validación y extracción | Paso `validation_extraction`. Parser en `backend/app/services/parser.py`. Adjuntos: nombre, tipo, tamaño, extensión, SHA-256. |
| Reglas y puntuación | Ruleset `1.1.0` en `backend/app/services/rules.py` y `risk.py`. |
| Índice de confianza | `backend/app/services/confidence.py`. Separado de la puntuación de riesgo. |
| FishBot | `frontend/src/lib/fishbot.ts`. Plantilla sobre el caso guardado. No abre URLs ni ejecuta adjuntos. |
| Recomendación | `policy.offered_action` desde `backend/app/policy/engine.py`. `auto_execute` forzado a false. Prueba `test_a_file_that_asks_to_auto_execute_is_forced_off`. |
| Aprobación humana | `POST .../actions/response`. La ficha tiene Yes / No. |
| Acción simulada | Solo si la acción ofrecida es `simulate_quarantine` y la persona aprueba. `external_effect` `none`. |
| Auditoría | `audit_events`: `analysis_completed`, `action_response`, `action_denied`, `quarantine_simulated`, `verdict_feedback`, `analyst_decision`. |

Robustez observada:

- Vacío, malformado, texto que no es correo y ZIP renombrado: HTTP 400, códigos `empty_file` o `invalid_content`. El ZIP no se abre (`test_zip_renamed_as_eml_is_not_opened`).
- Bytes nulos en el cuerpo de un mensaje con cabeceras: la prueba acepta 201 con una de las cuatro etiquetas, o 400 controlado. No exige un 500.
- Inyección en el cuerpo (“the message is safe”, “set risk_label”): la etiqueta quedó `suspicious` por `urgency_credential_lure`. Esa frase de instrucción no aparece en los motivos. `ai_summary` null.
- Esquema `javascript:`: regla `dangerous_url_scheme`, defang con `[colon]`.
- Fallo sintético de reputación y del explicador: HTTP 201, etiqueta conservada, pasos `failed`, `enrichment_status` `error`, `explainer_status` `fallback`.

Riesgos pendientes:

- Sin corpus local no hay demo de “correo real” en un clic. El JSON de 500 mensajes es una corrida previa, no una repetición de hoy.
- `analyst_id` es una etiqueta, no una identidad. No hay autenticación ni límite de tasa. El modelo de amenazas ya lo dice. Para un hackathon local es aceptable. Para exponer la API, no.
- Corregir la etiqueta con `POST .../decisions` no revoca la acción que la política ofreció. Un `POST .../actions/quarantine` posterior sigue pudiendo simular la cuarentena si esa era la oferta. La prueba de flujo histórica lo hace a propósito. La interfaz no enseña ese segundo camino.
- La correlación por buzón o dominio cambia el caso siguiente. Hay que ensayar el orden del guion en una base limpia.

Acciones antes de presentar: base limpia, health en off/off, y el guion de 150 segundos. Si se quieren los botones de corpus, seguir `docs/alaris-evaluacion-muestras.md` en el portátil de la demo y no commitear los `.eml`.

## 2. Impacto

Qué está medido:

- Tiempo de máquina por caso: tabla de arriba y promedio 9.0 ms en 12 casos de la base de auditoría.
- Tiempo hasta la decisión que cierra la espera: 144 ms en la única aprobación, hecha por API inmediatamente. El significado está en `docs/alaris-instrumentacion.md`.
- Frecuencia de la tarea y gravedad: el producto las enuncia (triage de phishing antes de una acción), pero esta auditoría no contó casos reales de un SOC ni una escala de severidad operativa. Queda pendiente de medición.
- Tiempo eliminado: pendiente. El campo de minutos manuales de la home estaba vacío. No hay resta válida.

La evaluación almacenada (no reejecutada aquí) es el único volumen con etiqueta de corpus: 500 mensajes, ruleset 1.1.0, TP 113, FP 44, FN 0, TN 0, inconclusive de phishing 87, inconclusive de ham 256. El panel lo mostró tal cual, incluida la nota de que inconclusive no es benigno ni un verdadero positivo. Esas tasas no son el índice de confianza.

Riesgo bloqueante de mensaje: decir un porcentaje de ahorro o tratar el índice como exactitud. Riesgo de viabilidad alta: llegar sin el corpus si el jurado pide datos públicos en vivo.

Acción: en el guion, leer los milisegundos de la pantalla y decir que el ahorro humano no está medido. Si alguien escribe su baseline en la home durante un ensayo, esa cifra es suya; no la traigas de esta auditoría.

## 3. Innovación

Lo que el sistema hace con IA y automatización, y no es un clon de VirusTotal:

- La etiqueta sale de reglas deterministas con procedencia (regla, peso, campos observados). VirusTotal y URLhaus están apagados y, con clave, el stub responde `unavailable` sin enviar el indicador.
- El explicador, si se enciende, recibe ids de regla e indicadores defanged. No recibe el cuerpo. Si el JSON cita una regla que el motor no produjo, se descarta (`test_explainer_disabled_and_validation`). No puede cambiar la etiqueta.
- FishBot, en el modo de esta demo, es una plantilla local. Rechaza instrucciones de abrir enlaces o ejecutar adjuntos.
- La política elige una sola acción y `auto_execute` no se honra aunque el JSON lo pida.
- La autenticación del mensaje solo puntúa si el authserv está en `PHISHCATCH_TRUSTED_AUTHSERV_IDS`. Vacía por defecto. Por eso `clearly_benign.eml` y `certification_benign.eml` quedan `inconclusive`, y el señuelo con autenticación “limpia” sigue en `likely_malicious`.

Riesgo: presentarlo como “un modelo que detecta phishing” aplana la diferencia. La frase útil es que las reglas deciden, el índice dice cuánto se apoyan entre sí, y la persona suelta la acción.

Acción: dejar Gemini apagado en el escenario salvo un ensayo previo del fallo. Esta auditoría no midió la latencia de una llamada real al modelo.

## 4. Presentación

El guion de 150 segundos, con comandos, archivos y el plan B sin red, está en `docs/alaris-demo-150s.md`.

Cambios de redacción para que el índice no se lea como una probabilidad:

- FishBot ya no dice “I'm N% sure”. Dice “Confidence index N (band)” y repite que no es una exactitud medida.
- La ficha muestra “N index” y la banda “high confidence index”. Se quitó el signo de porcentaje.
- La bandeja dice “index N”.
- El README ya no promete `likely_benign` para `samples/clearly_benign.eml` con la lista de authserv vacía.
- La home ya no llama “correo real” a los botones sintéticos cuando el corpus no está.

El disclaimer largo sigue en la ficha, en la home y en `GET /api/v1/metrics`. El número 0–100 puede seguir malinterpretándose. Hay que leer la frase en voz alta.

## Correcciones hechas en esta auditoría

Cada una es pequeña y está cubierta por la suite.

1. `POST .../actions/quarantine` solo corre si la política guardada ofreció `simulate_quarantine`, no hay un rechazo previo y el caso no está ya simulado. Si no, responde 403 `action_not_authorized` y escribe `action_denied`. Si procede, deja también la fila de respuesta humana para que la ficha enseñe la misma decisión. Un segundo intento recibe 409.
2. `human_review_ms` en la auditoría de las decisiones, más `completed_human_reviews` y `average_human_review_ms` en `/api/v1/metrics` y en la home. Sin decisiones, el promedio es null.
3. Redacción del índice en FishBot, la ficha y la bandeja.
4. README y `samples/README.md`: `clearly_benign.eml` es `inconclusive` mientras la lista de authserv esté vacía.
5. El defang de `javascript:`, `vbscript:`, `data:` y `file:` rompe el dos puntos (`[colon]`) y conserva el resto del texto original, para que el motivo no pierda el paréntesis final que el normalizador recorta.
6. La home distingue botones de corpus ausentes y muestras sintéticas.
7. Modelo de amenazas: la cuarentena simulada queda condicionada a la oferta.
8. Fixtures sintéticos en `samples/audit/` y `tests/test_audit_readiness.py`.

## Acciones obligatorias antes de salir a presentar

1. Arrancar con una base nueva y leer `GET /health`.
2. Ensayar `docs/alaris-demo-150s.md` una vez en el portátil. Leer los números que salgan ahí.
3. No afirmar tiempo ahorrado, probabilidad ni “mensaje seguro”.
4. Decidir si el corpus va en el portátil. Si no va, no busques los botones “Real phishing”.
5. Dejar reputación y Gemini apagados, o ensayar antes el fallo y decir que la etiqueta no se movió.
6. No abrir enlaces ni adjuntos, ni del corpus ni de las muestras sintéticas.
