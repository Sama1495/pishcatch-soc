# Guion en vivo de 150 segundos

Reloj de palabra: de 0:00 a 2:30. La máquina responde en milisegundos; el tiempo de cada tramo es para hablar. Los números de abajo salen de la corrida del 2026-10-24 en esta máquina, con reputación y Gemini apagados. Si la pantalla muestra otra cifra, se lee la pantalla.

La interfaz está en inglés. El correo de ejemplo puede estar en español. No se abre ningún enlace ni adjunto.

## Antes del reloj

En una terminal, desde la raíz del repositorio, con el entorno ya instalado (`backend/.venv` y `frontend/node_modules`):

```bash
rm -f /tmp/phishcatch-demo.db
cd backend
PHISHCATCH_DATABASE_URL=sqlite:////tmp/phishcatch-demo.db \
PHISHCATCH_REPUTATION_ENABLED=false \
PHISHCATCH_AI_ENABLED=false \
PHISHCATCH_TRUSTED_AUTHSERV_IDS= \
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8741
```

En otra terminal:

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 8742
```

Comprobar:

```bash
curl -s http://127.0.0.1:8741/health
```

Tiene que verse `reputation_enabled` en false y `explainer_provider` en `off`. En la corrida de auditoría la respuesta fue `ruleset` `1.1.0`.

Abrir http://127.0.0.1:8742 . Si el pack de corpus no está copiado, los botones visibles son los sintéticos de LinkedIn. El texto debe decir que los botones de corpus siguen ocultos. No los presentes como correo real.

## 0:00–0:20 · Problema

Un analista abre el mensaje, compara el enlace visible con el href, mira el pretexto y escribe el parte. PhishCatch deja hecho el expediente y la persona decide. No digas cuántos minutos ahorra: esa resta no está medida. Di que el tiempo de análisis queda en milisegundos en el caso y que el tiempo de revisión humana solo aparece cuando alguien decide.

## 0:20–0:50 · Caso con señales

Sube `samples/clearly_phishing.eml` desde la zona de carga, o:

```bash
curl -s -F "file=@samples/clearly_phishing.eml;type=message/rfc822" \
  http://127.0.0.1:8741/api/v1/incidents
```

En la corrida viva: HTTP 201, pared del cliente 93.7 ms, `processing_time_ms` 57, etiqueta `likely_malicious`, puntuación 100, índice de confianza 83, banda high, acción ofrecida `simulate_quarantine`, explicador `disabled`. La primera petición de esa serie fue la más lenta; las siguientes bajaron a 2–4 ms de procesamiento.

En la ficha, señala:

- índice de confianza, con la frase de que no es una exactitud medida ni una probabilidad;
- tres motivos (adjunto, enlace que no coincide, IP);
- URLs defanged, por ejemplo `hxxp://paypa1-secure[.]example/login`;
- “Auto-execute: off”.

FishBot arma el texto en el navegador. No llama a un modelo.

## 0:50–1:20 · La persona autoriza

En la ficha, “Yes, do this action”. O, con el id que devolvió el curl:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"decision":"approve","reason":"Demo approval.","analyst_id":"analyst.demo"}' \
  http://127.0.0.1:8741/api/v1/incidents/ID/actions/response
```

En la corrida viva esa llamada tardó 17.6 ms, `simulated` true, `external_effect` `none`, estado `quarantine_simulated`. El evento `action_response` guardó `authorization` `human_decision` y `human_review_ms` 144. Di en voz alta que 144 ms es el reloj hasta esa llamada, no el tiempo de un analista.

Opcional, mismo caso: “Agent was correct”. No cambia las reglas.

## 1:20–1:45 · Sin señales, y un fallo controlado

Sube `samples/no_signals.eml`.

En aislamiento y también en la serie viva (antes de mezclarlo con un caso sospechoso del mismo dominio): etiqueta `inconclusive`, puntuación 0, índice 38, banda low, acción `manual_investigation`. El aviso dice que el mensaje no se declara seguro. En el aislamiento de TestClient el procesamiento fue 2 ms y la única evidencia fue `no_suspicious_signals`.

Después sube `samples/malformed.eml`. En la serie viva: HTTP 400 en 2.2 ms, código `invalid_content`. Vuelve a `GET /health`: el proceso sigue.

No subas `samples/audit/synthetic_sparse.eml` después de `synthetic_prompt_injection.eml` si quieres mostrar “sin señales”. Comparten `audit-bot@example`. En una base nueva, el escueto queda `inconclusive` (índice 38, 20 ms en la primera petición de ese proceso de TestClient). Si el buzón ya está en un caso sospechoso, el siguiente mensaje dispara `related_indicator_in_prior_case`, puntuación 10, índice 47, etiqueta `suspicious`. Eso es contexto, no una prueba de que el segundo mensaje sea phishing.

## 1:45–2:10 · Innovación en un señuelo con autenticación no confiable

Pulsa “LinkedIn forged auth” o sube `samples/certification_lure_clean_auth.eml`.

En la serie viva: `likely_malicious`, puntuación 100, índice 76, banda high, cuarentena ofrecida, procesamiento 3 ms, pared 9.8 ms. Di que el SPF/DKIM/DMARC del mensaje no entra en la cuenta porque el authserv no está en la lista de confianza, y que el pretexto sí entra. La etiqueta la ponen las reglas. El explicador, apagado, no la escribe.

## 2:10–2:30 · Cifras que sí se pueden leer, y cierre

En la home, el panel “Measured evaluation” lee `backend/app/evaluation/latest.json`. En esta máquina el panel mostró ruleset 1.1.0, generado `2026-10-24T18:20:26+00:00`, n 500, TP 113, FP 44, FN 0, TN 0, phishing inconclusive 87, ham inconclusive 256, p50 5.446 ms, p95 31.113 ms, failures 0. Di que es la corrida almacenada, que esta demo no la recalculó, y que inconclusive no es “seguro”.

El promedio de procesamiento y el de revisión humana salen de la base local. Con la base de la auditoría, después de 12 casos y una sola aprobación por API, la home mostró 9 ms de promedio de análisis y 144 ms de revisión en 1 decisión. No conviertas eso en un porcentaje de ahorro.

## Si la red o el modelo fallan

El guion de arriba no necesita red ni clave. Si alguien enciende Gemini y la llamada falla, el paso `ai_explanation` queda `failed`, `explainer_status` pasa a `fallback` y la etiqueta no cambia. Lo cubre la prueba `test_explainer_and_reputation_outages_keep_the_label` con una excepción sintética, y las pruebas de Gemini para 429, JSON inválido y timeout. Esta auditoría no llamó a la API de Google.

Si los botones “Real phishing” no aparecen, no los improvises. Sigue con `clearly_phishing.eml`. Para tenerlos hace falta copiar extractos a `samples/demo-pack/` después de `scripts/fetch_datasets.py`, sin commitearlos y sin abrir sus enlaces. El procedimiento está en `docs/alaris-evaluacion-muestras.md`.

## Frases que no se dicen

- “Lo caza al 100 %.”
- “El mensaje es seguro.”
- “El índice es la probabilidad de acertar.”
- Un porcentaje de tiempo ahorrado.
- “Estos botones son correo real” cuando el corpus no está en disco.
