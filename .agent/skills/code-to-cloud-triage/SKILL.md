---
name: code-to-cloud-triage
description: Maps verified CodeMender code vulnerabilities in backend/app.py to deployed Google Cloud Run resources in Argolis (jmaciasc) via Wiz Security Graph (go/wiz-adatest), evaluates Toxic Combinations and Blast Radius, and generates Unified Vulnerability Management (UVM) payloads.
---

# Skill: Code-to-Cloud Triage & Blast Radius Analysis (`go/cm-wiz-skill`)

## Propósito
Esta skill implementa el patrón oficial de **Global Solutions CodeMender + Wiz Finding Evaluation (`go/cm-wiz-skill`)**. Conecta el análisis de código verificado por **CodeMender (`cm`)** en el repositorio local con el **Wiz Security Graph (`go/wiz-adatest`)** y el entorno **Google Cloud Run (`jmaciasc` / `599979914124`)** para identificar **Combinaciones Tóxicas (*Toxic Combinations*)** y priorizar la remediación según el riesgo real en la nube.

## Cuándo Usar Esta Skill
- Automáticamente después de que `evaluate-codemender-finding` confirma un hallazgo con `cm verify`.
- Cuando el equipo de AppSec, Cloud Infrastructure o SOC de Linktic desea conocer el **Blast Radius** en GCP de una vulnerabilidad en `backend/app.py`, `Dockerfile` o `terraform/main.tf`.
- Al ejecutar `bash scripts/demo_cli_runner.sh cm-wiz-triage`.

---

## Metodología de Correlación Code-to-Cloud

### 1. Mapeo de Artefacto de Código a Recurso Cloud Run (Code -> Container -> Cloud)
La skill traza la cadena completa de suministro de software:
- **Archivo fuente**: `backend/app.py` (Repositorio Git: `github.com/jmaciasc-google/linktic-devsecops-demo`)
- **Imagen de Contenedor**: `us-central1-docker.pkg.dev/jmaciasc/linktic-devsecops/linktic-sgda-portal:latest`
- **Servicio en Ejecución**: Google Cloud Run `linktic-sgda-portal` (`projects/jmaciasc/locations/us-central1/services/linktic-sgda-portal`, Project Number `599979914124`)
- **Identidad IAM Asociada**:
  - En estado pre-remediado (`terraform/main_vulnerable.tf.example`): Default Compute Service Account con `roles/editor` y variable `GEMINI_API_KEY` expuesta en texto plano.
  - En estado remediado (`terraform/main.tf`): Service Account dedicada `linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com` con mínimo privilegio y ADC.

### 2. Evaluación del Grafo de Ataque (Wiz Security Graph — Toxic Combination)
Al consultar `wizcli` (`artifacts/wizcli_scan_report.json`) y el tenant **Wiz (`go/wiz-adatest`)**, la skill evalúa los factores multiplicadores de riesgo:

```
[Internet Public Ingress (allUsers)]
        │
        ▼
[Cloud Run: linktic-sgda-portal (us-central1)]
        │
        ├──► Código Vulnerable: CM-SSRF-003 (CWE-918 en /api/webhooks/notify-entidad)
        │           │
        │           ▼
        │    [GCP Metadata Server: 169.254.169.254]
        │           │
        │           ▼
        │    [Robo de Token OAuth2 de Service Account]
        │           │
        │           ▼
        │    [Movimiento Lateral a Secret Manager + Citizen PII DB + Vertex AI]
        │
        └──► Código Vulnerable: CM-CMDI-002 (CWE-78) + Contenedor Root (UID 0 en v1)
                    │
                    ▼
             [Ejecución Remota de Comandos con Privilegios de Contenedor]
```

### 3. Reglas de Recálculo de Severidad (Risk Priority Recalculation)

| ID Hallazgo | CWE | Severidad Estática Base | Contexto Wiz Security Graph (`jmaciasc`) | Severidad Recalculada (UVM) | Acción en Pipeline (`cloudbuild.yaml`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`CM-SSRF-003`** | CWE-918 (SSRF) | `HIGH (7.5)` | Cloud Run expuesto a internet + acceso a `169.254.169.254` + token de Service Account con acceso a Secret Manager / datos ciudadanos | **`CRITICAL (9.8)` — TOXIC COMBINATION** | **BLOCK BUILD** + Aplicar allowlist HTTPS y bloqueo de IPs link-local |
| **`CM-SQLI-001`** | CWE-89 (SQLi) | `CRITICAL (9.4)` | Endpoint público `/api/radicados/search` conectado a base de datos con registros médicos ARL y fiduciarios (`confidencial=1`, Cédulas Colombianas) | **`CRITICAL (9.9)` — DATA EXFILTRATION PATH** | **BLOCK BUILD** + Parametrizar consultas SQLite (`?`) |
| **`CM-CMDI-002`** | CWE-78 / CWE-22 | `CRITICAL (9.6)` | Ejecución de `shell=True` en `/api/radicados/inspect-doc` combinada con proceso en contenedor | **`CRITICAL (9.8)` — RCE EN WORKLOAD CLOUD RUN** | **BLOCK BUILD** + Eliminar `shell=True`, confinar path y forzar `USER appuser (10001)` |

### 4. Estructura del Payload UVM (Unified Vulnerability Management)
Al finalizar la evaluación, la skill emite un payload JSON estructurado compatible con **Wiz UVM**, **Google Security Command Center (SCC)** y **Google SecOps SIEM/SOAR**:
```json
{
  "uvm_schema_version": "2.0",
  "correlation_id": "UVM-LINKTIC-2026-001",
  "skill": "code-to-cloud-triage (go/cm-wiz-skill)",
  "wiz_tenant": "go/wiz-adatest",
  "gcp_project_id": "jmaciasc",
  "gcp_project_number": "599979914124",
  "cloud_run_service": "projects/jmaciasc/locations/us-central1/services/linktic-sgda-portal",
  "service_account": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
  "toxic_combination_detected": true,
  "recalculated_risk_score": 9.9,
  "findings_correlated": ["CM-SQLI-001", "CM-CMDI-002", "CM-SSRF-003", "WIZ-IAC-001", "WIZ-IAC-002", "WIZ-DOCKER-001"],
  "remediation_status": "PATCHED_IN_V2_SECURE_AND_TERRAFORM_MAIN"
}
```
