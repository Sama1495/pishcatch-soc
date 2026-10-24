# Muestras sintéticas de auditoría

Estos archivos son **sintéticos**. No son correo real, no salen de un corpus público y no contienen malware. Los dominios usan el sufijo `.example` (RFC 2606). Sirven para la auditoría de preparación de Alaris y para las pruebas de `backend/tests/test_audit_readiness.py`.

No abras los enlaces ni los adjuntos. PhishCatch no los descarga ni los ejecuta.

| Archivo | Qué provoca |
| --- | --- |
| `synthetic_prompt_injection.eml` | El cuerpo pide declarar el mensaje seguro. También contiene un señuelo de credenciales. |
| `synthetic_contradictory.eml` | Acortador y una negación de cobro. La autenticación del mensaje no está en la lista de confianza. |
| `synthetic_javascript_url.eml` | Un enlace `javascript:` dentro de HTML. |
| `synthetic_sparse.eml` | Cabeceras mínimas, sin señales. |
| `synthetic_not_email.eml` | Texto que no es un mensaje. |
| `synthetic_risky_name.eml` | Nombre de adjunto con doble extensión. Los bytes son texto inofensivo. |
