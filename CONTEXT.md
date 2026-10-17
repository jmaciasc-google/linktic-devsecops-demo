# CONTEXT.md — Linktic SGDA & Claims AI Portal (Semantic Security Context for CodeMender & Antigravity)

## 1. Descripción del Sistema y Dominio de Negocio
**Linktic SGDA & Claims AI Portal** (*Sistema Inteligente de Radicación, Auditoría Documental y Triaje con IA*) es la plataforma de referencia de **Linktic** para tres verticales críticas en Colombia:
1. **Gobierno Digital y Gestión Documental (SGDA / PQRS)**: Radicación y trazabilidad de peticiones ciudadanas e interadministrativas (`*.gov.co`).
2. **Salud, ARL y Telemedicina (Caso tipo Positiva Compañía de Seguros)**: Auditoría clínica automatizada de reclamos médicos, incapacidades e historias clínicas con protección estricta de datos personales sensibles (Ley 1581 de 2012 — Habeas Data Colombia).
3. **Fiduciaria y Banca**: Desembolsos de encargos fiduciarios de alto valor y validación de garantías estatales.

Este archivo proporciona el contexto arquitectónico, las fronteras de confianza (*Trust Boundaries*) y los invariantes de seguridad formales para que **Google CodeMender (`cm find`, `cm verify`, `cm fix`)** y las skills de **Google Antigravity 2.0 (`evaluate-codemender-finding` y `code-to-cloud-triage`)** analicen, verifiquen mediante Exploit PoC en sandbox y parchen vulnerabilidades con **0% de falsos positivos**.

---

## 2. Arquitectura Técnica y Entorno Google Cloud (`jmaciasc` / `599979914124`)
- **Backend**: Python 3.11 + FastAPI (`backend/app.py`, `backend/security_modes.py`, `backend/seed_data.py`).
- **Frontend**: Single-Page Application ejecutiva (`frontend/index.html`) servida por FastAPI.
- **Base de Datos**: SQLite local (`/tmp/linktic_sgda.db`) pre-poblada con radicados públicos (`confidencial = 0`) y expedientes médicos/fiduciarios reservados (`confidencial = 1`) que contienen Cédulas de Ciudadanía Colombianas (CC), montos fiduciarios y diagnósticos clínicos.
- **Almacenamiento Documental (Sandbox)**: Directorio `/tmp/linktic_docs/` con anexos de radicados (`radicado_001.txt`, etc.).
- **IA Generativa y Guardrails Inline**:
  - **Vertex AI Gemini Enterprise** invocado mediante **Application Default Credentials (ADC / OAuth)** con **0% API Keys** en variables de entorno o código fuente.
  - **Google Cloud Model Armor + Cloud DLP** inline (`<30ms`) en `POST /api/ai/triage` para bloquear *Prompt Injection* directo/indirecto (`PI_AND_JAILBREAK`) y enmascarar PII colombiana (`SDP_DLP_COLOMBIA_CC`, tarjetas Visa/Mastercard y credenciales).
- **Infraestructura Cloud Run & CI/CD**:
  - Servicio Cloud Run v2: `linktic-sgda-portal` en `us-central1` (Proyecto Argolis: `jmaciasc` / Project Number: `599979914124`).
  - Identidad de Ejecución: Service Account dedicada de mínimo privilegio `linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com`.
  - Pipeline CI/CD: Google Cloud Build (`cloudbuild.yaml`) + Artifact Registry (`us-central1-docker.pkg.dev/jmaciasc/linktic-devsecops/linktic-sgda-portal`) + Wiz CLI (`wizcli`) + CodeMender SARIF Gate (`artifacts/results.sarif`).

---

## 3. Fronteras de Confianza (Trust Boundaries)

```
[ Ciudadano / Entidad Externa / Red Team ]
                   │
                   ▼ (Frontera 1: HTTP/JSON Untrusted Input)
┌──────────────────────────────────────────────────────────────────────┐
│ FastAPI Backend (backend/app.py) — Cloud Run (linktic-sgda-portal)   │
│                                                                      │
│  ├─► GET  /api/radicados/search?q=... ──► (Frontera 2: SQLite DB)    │
│  │                                        /tmp/linktic_sgda.db       │
│  │                                                                   │
│  ├─► POST /api/radicados/inspect-doc  ──► (Frontera 3: Filesystem)   │
│  │                                        /tmp/linktic_docs/         │
│  │                                                                   │
│  ├─► POST /api/webhooks/notify-entidad ─► (Frontera 4: Egress/Cloud) │
│  │                                        Bloqueo de 169.254.169.254 │
│  │                                                                   │
│  └─► POST /api/ai/triage ───────────────► (Frontera 5: Model Armor)  │
│                                           Vertex AI Gemini (ADC)     │
└──────────────────────────────────────────────────────────────────────┘
```

1. **Frontera 1 — Entrada HTTP No Confiable**: Todos los parámetros de consulta (`?q=`), cuerpos JSON (`filename`, `callback_url`, `prompt`) y encabezados provienen de redes públicas y deben tratarse como potencialmente maliciosos.
2. **Frontera 2 — Aislamiento de Registros Confidenciales en SQLite**: Las búsquedas públicas en `/api/radicados/search` jamás deben permitir alterar el predicado lógico `AND confidencial = 0`.
3. **Frontera 3 — Confinamiento de Archivos y Prohibición de Shell**: La inspección documental en `/api/radicados/inspect-doc` jamás debe invocar un intérprete de comandos (`sh`/`bash`) ni permitir navegación fuera de `/tmp/linktic_docs/`.
4. **Frontera 4 — Protección del Metadata Server de GCP y Red Interna**: El despachador de webhooks en `/api/webhooks/notify-entidad` se ejecuta dentro de Cloud Run con acceso al endpoint de metadatos (`http://169.254.169.254/computeMetadata/v1/` y `metadata.google.internal`). Ninguna solicitud externa puede forzar peticiones hacia IPs privadas, loopback o link-local.
5. **Frontera 5 — Firewall GenAI Inline (Model Armor + Cloud DLP)**: Ningún prompt de usuario ni documento adjunto puede enviarse a Vertex AI sin validación previa de *Prompt Injection* y desidentificación de PII colombiana.

---

## 4. Invariantes de Seguridad para CodeMender (`cm find`, `cm verify`, `cm fix`)

### Invariante 1: `CM-SQLI-001` — Prevención de SQL Injection (CWE-89) en `/api/radicados/search`
- **Riesgo**: La interpolación directa de cadenas (`f"SELECT * FROM radicados WHERE radicado_id LIKE '%{q}%' OR asunto LIKE '%{q}%' AND confidencial = 0"`) permite el payload `' OR '1'='1 --`, anulando el filtro `confidencial = 0` y exfiltrando reclamos médicos de ARL y fideicomisos reservados.
- **Regla de Remediación (`v2-secure`)**:
  - Usar exclusivamente consultas parametrizadas de SQLite (`?` placeholders):
    `SELECT * FROM radicados WHERE (radicado_id LIKE ? OR asunto LIKE ? OR entidad LIKE ?) AND confidencial = 0`
  - Validar longitud y patrones de inyección SQL antes de consultar la base de datos.

### Invariante 2: `CM-CMDI-002` — Prevención de OS Command Injection (CWE-78) y Path Traversal (CWE-22) en `/api/radicados/inspect-doc`
- **Riesgo**: El uso de `subprocess.run(f"wc -c /tmp/linktic_docs/{filename} && head -n 5 /tmp/linktic_docs/{filename}", shell=True)` permite inyectar comandos arbitrarios (`radicado_001.txt; id; uname -a`) o leer archivos del sistema (`../../../../etc/passwd`).
- **Regla de Remediación (`v2-secure`)**:
  - Prohibido usar `subprocess` con `shell=True` para procesar nombres de archivo.
  - Verificar estrictamente `Path(filename).name == filename`, rechazar `..`, `/` o metacaracteres (`;`, `|`, `&`, `$`, `` ` ``), confirmar que `target_path.resolve()` sea hijo directo de `/tmp/linktic_docs`, y calcular tamaño, hash SHA-256 y vista previa usando Python nativo.

### Invariante 3: `CM-SSRF-003` — Prevención de Server-Side Request Forgery (CWE-918) en `/api/webhooks/notify-entidad`
- **Riesgo (Toxic Combination con Wiz Security Graph)**: Si `callback_url` apunta a `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` o `metadata.google.internal`, un atacante externo puede robar el token OAuth2 de la Service Account del contenedor en Cloud Run y escalar privilegios hacia Secret Manager o bases de datos en GCP.
- **Regla de Remediación (`v2-secure`)**:
  - Exigir esquema `https://` estrictamente.
  - Validar que el hostname pertenezca a la lista blanca autorizada de entidades (`*.linktic.com`, `*.gov.co`, `api.positiva-sim.co`).
  - Bloquear explícitamente `localhost`, `metadata.google.internal` y todos los rangos IP privados, loopback y link-local (`169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) mediante `ipaddress`.

### Invariante 4: Hardening de Contenedor e Infraestructura como Código (Wiz CLI Gate)
- **Dockerfile**: Debe ejecutarse con usuario sin privilegios (`USER appuser`, UID `10001`), sin paquetes innecesarios y con `HEALTHCHECK` configurado.
- **Terraform (`terraform/main.tf`)**: Prohibido definir `GEMINI_API_KEY` en texto plano o asignar `roles/editor` a la cuenta de cómputo predeterminada. Se debe usar una Service Account dedicada (`linktic-sgda-runner`), Secret Manager, ADC y política WAF de Cloud Armor.
