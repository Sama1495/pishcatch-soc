# Procedimiento para muestras públicas o autorizadas

Este procedimiento sirve para puntuar correo cuyo origen está documentado. No abre adjuntos y no visita URLs del mensaje. PhishCatch solo lee bytes locales: cabeceras, texto, metadatos y un hash.

## Procedencia que este repositorio ya documenta

| Corpus | Papel | Origen | Licencia y cuidado |
| --- | --- | --- | --- |
| Jose Nazario, buzón `phishing-2023` | phishing, primeras 200 piezas en orden de buzón | https://monkey.org/~jose/phishing/phishing-2023 | CC-BY-4.0. Atribuir a Jose Nazario. |
| SpamAssassin `20030228_easy_ham` | ham, primeros 200 archivos por ruta ordenada | https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2 | Corpus público. El copyright sigue en quien envió el correo. No inyectar en un sistema de correo vivo. |
| SpamAssassin `20030228_hard_ham` | ham, primeros 100 archivos por ruta ordenada | https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2 | Igual que easy_ham. |

La selección fija, los límites y la lectura de tasas están en `docs/evaluation.md` y `docs/datasets.md`. El descargador es `scripts/fetch_datasets.py`. Guarda los archivos en `data/corpora/`, que está en `.gitignore`. También guarda `LICENSE.txt` y `README.txt` de Nazario. No recorre enlaces internos.

En esta auditoría el directorio `data/corpora/` no estaba en la máquina. No se volvió a ejecutar `python -m app.evaluate`. El panel sigue sirviendo `backend/app/evaluation/latest.json`, generado `2026-10-24T18:20:26+00:00`. Esas cifras son de esa corrida almacenada.

## Antes de descargar

1. Trabajar en una máquina local, sin publicar la API.
2. Confirmar que `PHISHCATCH_REPUTATION_ENABLED` queda en `false`. El adaptador de reputación, aunque se encienda, no implementa la consulta viva.
3. No configurar un cliente de correo que vaya a abrir el corpus.
4. No extraer adjuntos a un directorio que un visor vaya a ejecutar.

## Descarga y puntuación

Desde la raíz del repositorio:

```bash
python3 scripts/fetch_datasets.py
cd backend
.venv/bin/python -m app.evaluate
```

El evaluador lee el corpus ya descargado, parsea y aplica reglas. El módulo declara que no pide las URLs encontradas y no renderiza HTML. Escribe el resultado en `backend/app/evaluation/latest.json`. `GET /api/v1/evaluation` devuelve ese archivo. Si el archivo no está, la API responde `evaluation_not_run`.

No cambies la selección de mensajes después de ver los errores. `docs/datasets.md` pide editar el script si una URL de descarga se mueve, y no sustituir la muestra medida por otra.

## Cómo leer el resultado

- Positivo de predicción: `likely_malicious` o `suspicious`.
- Un phishing etiquetado `likely_benign` es falso negativo.
- Un ham etiquetado positivo es falso positivo.
- `inconclusive` no es verdadero positivo ni verdadero negativo, y no es una declaración de seguridad.
- `likely_benign` tampoco es un alta. Exige señales de alineación y el aviso dice que no prueban seguridad. Con la lista `PHISHCATCH_TRUSTED_AUTHSERV_IDS` vacía, un SPF/DKIM/DMARC del propio mensaje no cuenta.

## Muestras autorizadas que no son esos corpus

Si el equipo recibe un `.eml` con permiso escrito:

1. Anotar en el cuaderno de la demo: quién lo autorizó, fecha, alcance y que no es correo de cliente no autorizado.
2. Guardarlo fuera de git. No lo copies a `samples/` ni a `samples/demo-pack/` si el pack se va a commitear. `samples/demo-pack/*.eml` ya está ignorado.
3. Subirlo solo a la API local.
4. Comprobar en el caso que las URLs salen defanged y que el adjunto aparece como nombre, tipo, tamaño y SHA-256.
5. No pulsar un enlace, no copiar un `javascript:` a la barra del navegador y no abrir el adjunto.
6. La decisión de cuarentena sigue siendo simulada y exige la acción que la política ofreció.

## Muestras sintéticas de esta auditoría

`samples/audit/` es ficción, dominios `.example`, marcada como sintética. No sustituye al corpus público. Sirve para el flujo local y para `backend/tests/test_audit_readiness.py`. El índice de ese directorio está en `samples/audit/README.md`.

## Comprobaciones que no hay que saltarse

- Un archivo que no es correo debe terminar en error controlado (`invalid_content` o `empty_file`), con el proceso todavía en pie. `GET /health` después de esos rechazos.
- Un ZIP renombrado a `.eml` se rechaza con el mensaje de que no se abrió. Lo cubre `test_zip_renamed_as_eml_is_not_opened` y `test_not_email_and_zip_and_null_bytes_fail_closed`.
- Si el explicador o la reputación lanzan una excepción, el caso se guarda igual. Lo cubre `test_explainer_and_reputation_outages_keep_the_label`.
