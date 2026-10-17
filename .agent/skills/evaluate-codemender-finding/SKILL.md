---
name: evaluate-codemender-finding
description: Evaluates, empirically verifies in an isolated sandbox, and patches vulnerabilities discovered by Google CodeMender (cm), then triggers code-to-cloud-triage with Wiz Security Graph (go/cm-wiz-skill).
---

# Skill: Evaluate CodeMender Finding (`go/cm-wiz-skill`)

## Propósito
Esta skill de **Google Antigravity 2.0** orquesta el ciclo autónomo de remediación de **CodeMender (`cm`)** sobre el repositorio **Linktic SGDA & Claims AI Portal** y enlaza cada hallazgo verificado con la skill **`code-to-cloud-triage`** para calcular su radio de explosión (*Blast Radius*) en **Google Cloud Run (`jmaciasc`)** usando **Wiz Security Graph (`go/wiz-adatest`)**.

## Cuándo Usar Esta Skill
- Cuando el desarrollador o ingeniero de AppSec ejecuta un escaneo de **CodeMender** (`cm find` o `bash scripts/demo_cli_runner.sh cm-find`).
- Cuando existen hallazgos pendientes en `artifacts/results.sarif` o `cm report --format json`.
- Antes de aprobar un Pull Request o ejecutar el gate de seguridad en **Google Cloud Build (`cloudbuild.yaml`)**.

---

## Flujo de Ejecución Paso a Paso

### Paso 1: Ingesta de Contexto Semántico (`CONTEXT.md`) y Reporte de Hallazgos
1. Lee `CONTEXT.md` y `.codemender/config.yaml` para cargar las fronteras de confianza (*Trust Boundaries*) e invariantes de seguridad del portal SGDA de Linktic.
2. Obtiene la lista de vulnerabilidades detectadas por `gemini-3.8-flash-cyber`:
   ```bash
   bash scripts/demo_cli_runner.sh cm-find
   ```
3. Parsea los hallazgos activos en `backend/app.py`:
   - **`CM-SQLI-001` (CWE-89 — SQL Injection)** en `GET /api/radicados/search`.
   - **`CM-CMDI-002` (CWE-78 / CWE-22 — OS Command Injection & Path Traversal)** en `POST /api/radicados/inspect-doc`.
   - **`CM-SSRF-003` (CWE-918 — Server-Side Request Forgery)** en `POST /api/webhooks/notify-entidad`.

### Paso 2: Verificación Empírica en Sandbox Aislado (`cm verify` — 0% Falsos Positivos)
Para cada hallazgo, CodeMender **no se limita a análisis estático (SAST)**: levanta el servicio en un sandbox efímero y ejecuta un **Exploit PoC real**:
```bash
bash scripts/demo_cli_runner.sh cm-verify
```
- **Criterio de Aprobación de Verificación**:
  - `CM-SQLI-001`: El payload `' OR '1'='1 --` devuelve registros con `confidencial = 1` (reclamos médicos ARL y fideicomisos reservados). Confianza: **100% (`VERIFIED_EXPLOITABLE`)**.
  - `CM-CMDI-002`: El payload `radicado_001.txt; id; uname -a` ejecuta comandos del sistema operativo dentro del sandbox. Confianza: **100% (`VERIFIED_EXPLOITABLE`)**.
  - `CM-SSRF-003`: El payload `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` extrae el token OAuth2 del Metadata Server simulado/real. Confianza: **100% (`VERIFIED_EXPLOITABLE`)**.
- Si un hallazgo no es explotable en el sandbox, se descarta automáticamente para garantizar **0% de falsos positivos** al equipo de desarrollo de Linktic.

### Paso 3: Invocación de Correlación Code-to-Cloud (`code-to-cloud-triage`)
Para cada hallazgo con estado `VERIFIED_EXPLOITABLE`, invoca inmediatamente la skill [`.agent/skills/code-to-cloud-triage/SKILL.md`](../code-to-cloud-triage/SKILL.md):
```bash
bash scripts/demo_cli_runner.sh cm-wiz-triage
```
- Esto cruza la línea exacta de código en `backend/app.py` con la topología en vivo de **Wiz (`go/wiz-adatest`)** en el proyecto Argolis `jmaciasc` (`599979914124`) y recalcula la prioridad de remediación según exposición en internet y permisos IAM.

### Paso 4: Síntesis de Parche Autónomo y Re-Verificación (`cm fix`)
1. Genera el parche mínimo seguro con **Gemini 3.1 Pro** respetando los invariantes de `CONTEXT.md`:
   ```bash
   bash scripts/demo_cli_runner.sh cm-fix
   ```
2. Ejecuta la suite completa de pruebas funcionales y de seguridad:
   ```bash
   pytest tests/test_app_and_security.py -v
   ```
3. Re-ejecuta los 3 Exploits PoC contra el código parcheado (`v2-secure`) confirmando que el 100% de los vectores son bloqueados (`HTTP 400/403`) sin degradar la funcionalidad del negocio.
4. Actualiza `artifacts/results.sarif` y `artifacts/codemender_report.html` mediante:
   ```bash
   bash scripts/demo_cli_runner.sh cm-report
   ```
