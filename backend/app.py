"""FastAPI Application for Linktic SGDA & Claims AI Portal.

Sistema Inteligente de Radicación, Auditoría Documental y Triaje con IA
(Gobierno SGDA/PQRS, Salud/ARL Positiva, y Sector Fiduciario/Banca).
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.security_modes import (
    VALID_MODES,
    get_current_mode,
    get_pipeline_summary_data,
    inspect_prompt_with_model_armor,
    is_metadata_or_internal_target,
    set_current_mode,
    validate_webhook_url_secure,
)
from backend.seed_data import DB_PATH, DOCS_DIR, init_db_and_docs

REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_INDEX = REPO_ROOT / "frontend" / "index.html"
ARTIFACTS_DIR = REPO_ROOT / "artifacts"

# Ensure SQLite DB and sample docs exist immediately on import
init_db_and_docs()


# ---------------------------------------------------------------------------
# In-Memory Cloud Trace + Cloud Audit Log + Google SecOps UDM Telemetry Store
# ---------------------------------------------------------------------------
_TELEMETRY_LOGS: List[Dict[str, Any]] = []


def record_telemetry_event(
    action: str,
    endpoint: str,
    security_mode: str,
    status: str,
    latency_ms: float,
    principal_email: str = "admin@jmaciasc.altostrat.com",
    caller_ip: str = "181.54.112.40",
    model_armor_verdict: str = "N/A",
    secops_rule_match: str = "NONE (NORMAL_TRAFFIC)",
    gti_threat_actor_context: str = "Benign Operational Activity — Linktic SGDA Portal",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Appends a structured Cloud Trace + Google SecOps UDM telemetry event."""
    trace_id = uuid.uuid4().hex
    span_id = uuid.uuid4().hex[:16]
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "projectId": "jmaciasc",
        "projectNumber": "599979914124",
        "serviceName": "linktic-sgda-portal",
        "region": "us-central1",
        "action": action,
        "endpoint": endpoint,
        "securityMode": security_mode,
        "status": status,
        "principalEmail": principal_email,
        "serviceAccountIdentity": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
        "callerIp": caller_ip,
        "traceId": f"projects/jmaciasc/traces/{trace_id}",
        "traceIdShort": trace_id,
        "spanId": span_id,
        "latencyMs": round(latency_ms, 2),
        "modelArmorVerdict": model_armor_verdict,
        "secopsRuleMatch": secops_rule_match,
        "gtiThreatActorContext": gti_threat_actor_context,
        "details": details or {},
    }
    _TELEMETRY_LOGS.insert(0, event)
    if len(_TELEMETRY_LOGS) > 50:
        _TELEMETRY_LOGS.pop()
    return event


def _seed_initial_telemetry() -> None:
    """Seeds baseline operational and security telemetry spans for immediate SOC visibility."""
    if _TELEMETRY_LOGS:
        return
    record_telemetry_event(
        action="SYSTEM_STARTUP_ADC_VERIFIED",
        endpoint="GET /api/health",
        security_mode=get_current_mode(),
        status="OK",
        latency_ms=3.2,
        principal_email="linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
        caller_ip="10.128.0.14",
        model_armor_verdict="TEMPLATE_ACTIVE (linktic-sgda-armor-v2)",
        secops_rule_match="NONE (ADC_IAM_FEDERATION_VERIFIED)",
        gti_threat_actor_context="0% API Keys in Code — Verified by Wiz CLI & Antigravity Governance",
    )
    record_telemetry_event(
        action="AI_TRIAGE_ARL_POSITIVA",
        endpoint="POST /api/ai/triage",
        security_mode="v2-secure",
        status="SANITIZED_AND_APPROVED",
        latency_ms=14.6,
        principal_email="auditor.medico@linktic.com",
        caller_ip="181.54.112.40",
        model_armor_verdict="MATCH_FOUND: SDP_DLP_COLOMBIA_CC (PII_MASKED_INLINE)",
        secops_rule_match="DLP_COLOMBIA_LEY_1581_PII_MASKED",
        gti_threat_actor_context="Legitimate ARL Medical Triage — Citizen Cédula Masked Inline (<30ms)",
    )


_seed_initial_telemetry()


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initializes SQLite DB and sample documents on FastAPI server startup."""
    init_db_and_docs()
    _seed_initial_telemetry()
    yield


app = FastAPI(
    title="Linktic SGDA & Claims AI Portal",
    description=(
        "Sistema Inteligente de Radicación, Auditoría Documental y Triaje con IA — "
        "Demo End-to-End DevSecOps con Google Antigravity, CodeMender, Wiz, Model Armor y Google SecOps."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic Request Models
# ---------------------------------------------------------------------------
class ModeSwitchRequest(BaseModel):
    mode: str = Field(..., description="Modo de seguridad: 'v1-vulnerable' o 'v2-secure'")


class InspectDocRequest(BaseModel):
    filename: str = Field(
        default="radicado_001.txt",
        description="Nombre del archivo en /tmp/linktic_docs/",
    )


class WebhookNotifyRequest(BaseModel):
    radicado_id: str = Field(default="RAD-2026-00101", description="ID del radicado a notificar")
    callback_url: str = Field(
        ...,
        description="URL del webhook de la entidad aliada (ej. https://api.positiva-sim.co/webhook)",
    )


class AiTriageRequest(BaseModel):
    radicado_id: str = Field(default="RAD-2026-00101", description="ID del radicado bajo auditoría")
    prompt: str = Field(..., description="Instrucción o consulta de triaje para el agente Gemini")
    model_armor_enabled: bool = Field(
        default=True,
        description="Activa o desactiva el guardrail en línea de Model Armor + Cloud DLP (<30ms)",
    )


# ---------------------------------------------------------------------------
# Helper: Row Serialization
# ---------------------------------------------------------------------------
def _row_to_dict(cursor: sqlite3.Cursor, row: tuple) -> Dict[str, Any]:
    cols = [col[0] for col in cursor.description]
    item = dict(zip(cols, row))
    # Provide aliases so frontend, notebook, and tests can read any standard key
    cc = item.get("ciudadano_cedula", "")
    item["ciudadano_cc"] = cc
    item["cedula"] = cc
    item["confidencial_bool"] = bool(item.get("confidencial", 0))
    return item


def _query_radicados_public() -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        init_db_and_docs()
    conn = sqlite3.connect(str(DB_PATH))
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM radicados WHERE confidencial = 0 ORDER BY id ASC")
        rows = cursor.fetchall()
        return [_row_to_dict(cursor, r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Frontend & Artifacts Routes
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_frontend() -> HTMLResponse:
    """Serves ../frontend/index.html with a clean HTML fallback if not yet built."""
    if FRONTEND_INDEX.exists():
        return HTMLResponse(content=FRONTEND_INDEX.read_text(encoding="utf-8"), status_code=200)
    fallback_html = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><title>Linktic SGDA & Claims AI Portal</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 2rem;">
  <h1>🛡️ Linktic SGDA & Claims AI Portal — Backend Operativo</h1>
  <p>El backend FastAPI está activo en modo <strong>v2-secure</strong> (Proyecto GCP: <code>jmaciasc</code> / <code>599979914124</code>).</p>
  <ul>
    <li><a href="/api/health" style="color: #38bdf8;">GET /api/health</a></li>
    <li><a href="/api/radicados" style="color: #38bdf8;">GET /api/radicados</a></li>
    <li><a href="/api/pipeline/summary" style="color: #38bdf8;">GET /api/pipeline/summary</a></li>
    <li><a href="/api/telemetry/logs" style="color: #38bdf8;">GET /api/telemetry/logs</a></li>
  </ul>
</body>
</html>"""
    return HTMLResponse(content=fallback_html, status_code=200)


@app.get("/artifacts/{filename}")
async def serve_artifact(filename: str):
    """Serves static security artifacts (codemender_report.html, results.sarif, wizcli_scan_report.json)."""
    if Path(filename).name != filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Nombre de artefacto inválido.")
    target = (ARTIFACTS_DIR / filename).resolve()
    if target.parent != ARTIFACTS_DIR.resolve() or not target.exists():
        raise HTTPException(status_code=404, detail=f"Artefacto '{filename}' no encontrado.")
    media_type = "text/html" if filename.endswith(".html") else "application/json"
    return FileResponse(path=str(target), media_type=media_type)


# ---------------------------------------------------------------------------
# Health & Mode Management Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def api_health(mode: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Returns service health, active security mode, GCP project metadata, ADC status, and Model Armor status."""
    active_mode = get_current_mode(mode)
    return {
        "status": "healthy",
        "service": "linktic-sgda-portal",
        "portal_name": "Linktic SGDA & Claims AI Portal (Radicación, Auditoría Documental y Triaje IA)",
        "version": "2.0.0",
        "mode": active_mode,
        "security_mode": active_mode,
        "gcp_project": {
            "project_id": "jmaciasc",
            "project_number": "599979914124",
            "region": "us-central1",
            "cloud_run_service": "linktic-sgda-portal",
        },
        "project_id": "jmaciasc",
        "project_number": "599979914124",
        "adc_identity_status": {
            "authenticated": True,
            "mode": "Application Default Credentials (ADC)",
            "service_account": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
            "principal_email": "admin@jmaciasc.altostrat.com",
            "hardcoded_api_keys_count": 0,
            "positiva_sgda_key_leak_prevented": True,
        },
        "model_armor_status": {
            "enabled": True,
            "inline_sla_ms": 30,
            "template": "projects/jmaciasc/locations/us-central1/templates/linktic-sgda-armor-v2",
            "dlp_deidentify_template": "projects/jmaciasc/locations/us-central1/deidentifyTemplates/linktic-colombia-cc-v2",
            "active_detectors": [
                "PI_AND_JAILBREAK",
                "SDP_DLP_COLOMBIA_CC",
                "SDP_DLP_CREDIT_CARD",
                "SDP_DLP_CREDENTIALS_AND_KEYS",
                "MALICIOUS_URI_FILTER",
            ],
        },
        "mcp_servers": {
            "google_secops_siem_soar": "ONLINE (secops-mcp-server / us-central1)",
            "google_threat_intelligence_madiant": "ONLINE (gti-mcp-server / us-central1)",
        },
    }


@app.get("/api/mode")
async def get_mode(mode: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Returns the current runtime security mode."""
    active_mode = get_current_mode(mode)
    return {
        "mode": active_mode,
        "security_mode": active_mode,
        "valid_modes": list(VALID_MODES),
        "description": (
            "Código remediado por CodeMender + Wiz + Model Armor"
            if active_mode == "v2-secure"
            else "Modo vulnerable sin guardrails (CWE-89 SQLi, CWE-78 CmdInj, CWE-918 SSRF expuestos)"
        ),
    }


@app.post("/api/mode")
async def switch_mode(payload: ModeSwitchRequest, request: Request) -> Dict[str, Any]:
    """Switches the live backend runtime mode between v1-vulnerable and v2-secure."""
    t0 = time.perf_counter()
    try:
        updated = set_current_mode(payload.mode.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    latency = (time.perf_counter() - t0) * 1000.0 + 1.2
    caller_ip = request.client.host if request.client else "181.54.112.40"
    record_telemetry_event(
        action=f"RUNTIME_MODE_SWITCH -> {updated}",
        endpoint="POST /api/mode",
        security_mode=updated,
        status="MODE_UPDATED",
        latency_ms=latency,
        caller_ip=caller_ip,
        model_armor_verdict="ACTIVE" if updated == "v2-secure" else "WARNING_V1_VULNERABLE_MODE",
        secops_rule_match=(
            "AUDIT_SECURITY_POSTURE_HARDENED"
            if updated == "v2-secure"
            else "ALERT_SECURITY_GUARDRAILS_DISABLED_FOR_DEMO"
        ),
        gti_threat_actor_context=f"Runtime posture switched to {updated} by presenter",
    )
    return {
        "status": "updated",
        "mode": updated,
        "security_mode": updated,
        "message": f"Modo de seguridad actualizado exitosamente a '{updated}'.",
    }


# ---------------------------------------------------------------------------
# Radicados Listing & Search (CWE-89 SQL Injection Demo vs Remediation)
# ---------------------------------------------------------------------------
@app.get("/api/radicados")
async def list_public_radicados(mode: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Lists public (non-confidential) radicados across SGDA, ARL Medical Claims, and Fiduciary verticals."""
    active_mode = get_current_mode(mode)
    items = _query_radicados_public()
    return {
        "mode": active_mode,
        "security_mode": active_mode,
        "count": len(items),
        "radicados": items,
        "results": items,
        "data": items,
        "items": items,
    }


@app.get("/api/radicados/search")
async def search_radicados(
    request: Request,
    q: str = Query(default="", description="Término de búsqueda por radicado_id, entidad o asunto"),
    mode: Optional[str] = Query(default=None, description="Override opcional: v1-vulnerable o v2-secure"),
):
    """Searches radicados. Demonstrates CWE-89 SQL Injection in v1-vulnerable vs parameterized SQL in v2-secure."""
    t0 = time.perf_counter()
    active_mode = get_current_mode(mode)
    caller_ip = request.client.host if request.client else "181.54.112.40"

    if not DB_PATH.exists():
        init_db_and_docs()

    # Check for suspicious SQLi tokens for telemetry & v2-secure input validation
    sqli_indicators = ("'", "--", ";", "/*", "*/", " or ", "union ", "drop ", "1=1", "'1'='1")
    q_lower = q.lower()
    is_sqli_attempt = any(tok in q_lower for tok in sqli_indicators)

    if active_mode == "v1-vulnerable":
        # -------------------------------------------------------------------
        # VULNERABLE PATH (CM-SQLI-001 / CWE-89): Unsafe f-string SQL query
        # -------------------------------------------------------------------
        raw_sql = (
            f"SELECT * FROM radicados WHERE radicado_id LIKE '%{q}%' "
            f"OR asunto LIKE '%{q}%' AND confidencial = 0"
        )
        conn = sqlite3.connect(str(DB_PATH))
        try:
            cursor = conn.cursor()
            cursor.execute(raw_sql)
            rows = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
        except sqlite3.Error as db_err:
            rows = []
            raw_sql = f"{raw_sql} -- [SQLite Error: {db_err}]"
        finally:
            conn.close()

        leaked_conf = [r for r in rows if r.get("confidencial") in (1, True)]
        latency = (time.perf_counter() - t0) * 1000.0 + 4.1

        record_telemetry_event(
            action="RADICADOS_SEARCH_SQLI_EXPLOITED" if leaked_conf else "RADICADOS_SEARCH_V1",
            endpoint="GET /api/radicados/search",
            security_mode="v1-vulnerable",
            status="COMPROMISED_DATA_EXFILTRATION" if leaked_conf else "OK",
            latency_ms=latency,
            principal_email="anonymous-attacker@untrusted.net" if leaked_conf else "operador.sgda@linktic.com",
            caller_ip="45.155.205.233" if leaked_conf else caller_ip,
            model_armor_verdict="NOT_APPLICABLE_SQL_LAYER",
            secops_rule_match=(
                "CRITICAL_YARAL_SQLI_CWE89_CONFIDENTIAL_LEAK"
                if leaked_conf
                else "NONE"
            ),
            gti_threat_actor_context=(
                "GTI Match: UNC-ColFinancial-SQLi — Exfiltration of Fiduciary & Medical Reserve Records (Ley 23/1981)"
                if leaked_conf
                else "Normal SGDA search query"
            ),
            details={
                "query": q,
                "raw_sql": raw_sql,
                "leaked_confidential_records": len(leaked_conf),
            },
        )

        return {
            "status": "exploited" if leaked_conf else "ok",
            "mode": "v1-vulnerable",
            "security_mode": "v1-vulnerable",
            "finding_id": "CM-SQLI-001",
            "cwe": "CWE-89",
            "query": q,
            "sql_executed": raw_sql,
            "exploited": len(leaked_conf) > 0,
            "leaked_confidential_count": len(leaked_conf),
            "count": len(rows),
            "radicados": rows,
            "results": rows,
            "data": rows,
            "items": rows,
        }

    # -----------------------------------------------------------------------
    # SECURE PATH (v2-secure — Patched by CodeMender CM-SQLI-001)
    # Strict input validation + Parameterized SQLite query (?)
    # -----------------------------------------------------------------------
    if is_sqli_attempt:
        latency = (time.perf_counter() - t0) * 1000.0 + 2.3
        record_telemetry_event(
            action="RADICADOS_SEARCH_SQLI_BLOCKED",
            endpoint="GET /api/radicados/search",
            security_mode="v2-secure",
            status="BLOCKED_BY_CODEMENDER_PATCH",
            latency_ms=latency,
            principal_email="anonymous-attacker@untrusted.net",
            caller_ip="45.155.205.233",
            model_armor_verdict="WAF_AND_PARAMETERIZED_QUERY_ENFORCED",
            secops_rule_match="BLOCKED_YARAL_SQLI_ATTEMPT_CM_SQLI_001",
            gti_threat_actor_context="Blocked SQLi payload targeting Colombian Fiduciary & ARL Citizen Records",
            details={"blocked_query": q, "finding_id": "CM-SQLI-001"},
        )
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "blocked": True,
                "mode": "v2-secure",
                "security_mode": "v2-secure",
                "finding_id": "CM-SQLI-001",
                "cwe": "CWE-89",
                "query": q,
                "message": (
                    "Ataque de SQL Injection (CWE-89) bloqueado por el parche de CodeMender (CM-SQLI-001): "
                    "Validación estricta de entrada y consultas SQLite parametrizadas (?) activas."
                ),
                "leaked_confidential_count": 0,
                "count": 0,
                "radicados": [],
                "results": [],
                "data": [],
                "items": [],
            },
        )

    conn = sqlite3.connect(str(DB_PATH))
    try:
        cursor = conn.cursor()
        like_param = f"%{q}%"
        cursor.execute(
            """
            SELECT * FROM radicados
            WHERE (radicado_id LIKE ? OR asunto LIKE ? OR entidad LIKE ? OR vertical LIKE ?)
              AND confidencial = 0
            ORDER BY id ASC
            """,
            (like_param, like_param, like_param, like_param),
        )
        rows = [_row_to_dict(cursor, r) for r in cursor.fetchall()]
    finally:
        conn.close()

    latency = (time.perf_counter() - t0) * 1000.0 + 2.5
    record_telemetry_event(
        action="RADICADOS_SEARCH_SECURE",
        endpoint="GET /api/radicados/search",
        security_mode="v2-secure",
        status="OK",
        latency_ms=latency,
        principal_email="operador.sgda@linktic.com",
        caller_ip=caller_ip,
        secops_rule_match="NONE (PARAMETERIZED_QUERY_SAFE)",
        details={"query": q, "returned_rows": len(rows)},
    )
    return {
        "status": "ok",
        "blocked": False,
        "mode": "v2-secure",
        "security_mode": "v2-secure",
        "finding_id": "CM-SQLI-001",
        "query": q,
        "sql_executed": "SELECT * FROM radicados WHERE (radicado_id LIKE ? OR asunto LIKE ?) AND confidencial = 0 [PARAMETERIZED]",
        "exploited": False,
        "leaked_confidential_count": 0,
        "count": len(rows),
        "radicados": rows,
        "results": rows,
        "data": rows,
        "items": rows,
    }


# ---------------------------------------------------------------------------
# Document Inspector (CWE-78 OS Command Injection & CWE-22 Path Traversal)
# ---------------------------------------------------------------------------
@app.post("/api/radicados/inspect-doc")
async def inspect_document(
    payload: InspectDocRequest,
    request: Request,
    mode: Optional[str] = Query(default=None),
):
    """Inspects an attached SGDA document. Demonstrates CWE-78/CWE-22 in v1-vulnerable vs sandbox in v2-secure."""
    t0 = time.perf_counter()
    active_mode = get_current_mode(mode)
    filename = payload.filename.strip()
    caller_ip = request.client.host if request.client else "181.54.112.40"

    if not DOCS_DIR.exists():
        init_db_and_docs()

    if active_mode == "v1-vulnerable":
        # -------------------------------------------------------------------
        # VULNERABLE PATH (CM-CMDI-002 / CWE-78 & CWE-22): shell=True execution
        # -------------------------------------------------------------------
        cmd = f"wc -c /tmp/linktic_docs/{filename} && head -n 5 /tmp/linktic_docs/{filename}"
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        combined_output = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        is_rce_or_lfi = any(
            sep in filename for sep in (";", "|", "&", "$", "`", "..", "/etc/")
        )
        latency = (time.perf_counter() - t0) * 1000.0 + 8.4

        record_telemetry_event(
            action="DOC_INSPECT_RCE_EXPLOITED" if is_rce_or_lfi else "DOC_INSPECT_V1",
            endpoint="POST /api/radicados/inspect-doc",
            security_mode="v1-vulnerable",
            status="COMPROMISED_CONTAINER_RCE" if is_rce_or_lfi else "OK",
            latency_ms=latency,
            principal_email="anonymous-attacker@untrusted.net" if is_rce_or_lfi else "auditor.sgda@linktic.com",
            caller_ip="185.220.101.19" if is_rce_or_lfi else caller_ip,
            secops_rule_match=(
                "CRITICAL_YARAL_OS_COMMAND_INJECTION_CWE78"
                if is_rce_or_lfi
                else "NONE"
            ),
            gti_threat_actor_context=(
                "GTI Match: Container Shell Spawning (/bin/sh -c) via Unsanitized Document Inspector"
                if is_rce_or_lfi
                else "Standard document inspection"
            ),
            details={"filename": filename, "command_executed": cmd},
        )

        return {
            "status": "exploited" if is_rce_or_lfi else "ok",
            "mode": "v1-vulnerable",
            "security_mode": "v1-vulnerable",
            "finding_id": "CM-CMDI-002",
            "cwe": "CWE-78 / CWE-22",
            "filename": filename,
            "command_executed": cmd,
            "exploited": is_rce_or_lfi,
            "returncode": proc.returncode,
            "output": combined_output.strip(),
            "preview": combined_output.strip(),
        }

    # -----------------------------------------------------------------------
    # SECURE PATH (v2-secure — Patched by CodeMender CM-CMDI-002)
    # Strict basename check, Path.resolve() sandbox confinement, pure Python
    # -----------------------------------------------------------------------
    has_bad_chars = any(sep in filename for sep in (";", "|", "&", "$", "`", "\n", "\r", "..", "/", "\\"))
    if has_bad_chars or Path(filename).name != filename:
        latency = (time.perf_counter() - t0) * 1000.0 + 1.9
        record_telemetry_event(
            action="DOC_INSPECT_RCE_BLOCKED",
            endpoint="POST /api/radicados/inspect-doc",
            security_mode="v2-secure",
            status="BLOCKED_BY_CODEMENDER_PATCH",
            latency_ms=latency,
            principal_email="anonymous-attacker@untrusted.net",
            caller_ip="185.220.101.19",
            secops_rule_match="BLOCKED_YARAL_CMD_INJECTION_AND_PATH_TRAVERSAL_CM_CMDI_002",
            gti_threat_actor_context="Blocked CWE-78 OS Command Injection & CWE-22 Path Traversal attempt",
            details={"blocked_filename": filename, "finding_id": "CM-CMDI-002"},
        )
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "blocked": True,
                "mode": "v2-secure",
                "security_mode": "v2-secure",
                "finding_id": "CM-CMDI-002",
                "cwe": "CWE-78 / CWE-22",
                "filename": filename,
                "message": (
                    "Ataque de OS Command Injection / Path Traversal (CWE-78 / CWE-22) bloqueado por el parche "
                    "de CodeMender (CM-CMDI-002): `shell=True` eliminado y ruta confinada a `/tmp/linktic_docs`."
                ),
            },
        )

    docs_root = DOCS_DIR.resolve()
    resolved_path = (docs_root / filename).resolve()
    if resolved_path.parent != docs_root or not resolved_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Documento '{filename}' no encontrado dentro del sandbox documental autorizado.",
        )

    raw_bytes = resolved_path.read_bytes()
    text_content = raw_bytes.decode("utf-8", errors="replace")
    preview_lines = "\n".join(text_content.splitlines()[:5])
    sha256_digest = hashlib.sha256(raw_bytes).hexdigest()

    latency = (time.perf_counter() - t0) * 1000.0 + 2.1
    record_telemetry_event(
        action="DOC_INSPECT_SECURE",
        endpoint="POST /api/radicados/inspect-doc",
        security_mode="v2-secure",
        status="OK",
        latency_ms=latency,
        principal_email="auditor.sgda@linktic.com",
        caller_ip=caller_ip,
        secops_rule_match="NONE (PURE_PYTHON_SANDBOX_VERIFIED)",
        details={"filename": filename, "sha256": sha256_digest, "size_bytes": len(raw_bytes)},
    )

    return {
        "status": "ok",
        "blocked": False,
        "mode": "v2-secure",
        "security_mode": "v2-secure",
        "finding_id": "CM-CMDI-002",
        "filename": filename,
        "sandbox_verified": True,
        "size_bytes": len(raw_bytes),
        "sha256": sha256_digest,
        "preview": preview_lines,
        "output": f"Bytes: {len(raw_bytes)} | SHA-256: {sha256_digest}\n{preview_lines}",
    }


# ---------------------------------------------------------------------------
# Webhook Notifier (CWE-918 SSRF & Wiz Toxic Combination Demo vs Remediation)
# ---------------------------------------------------------------------------
@app.post("/api/webhooks/notify-entidad")
async def notify_entidad_webhook(
    payload: WebhookNotifyRequest,
    request: Request,
    mode: Optional[str] = Query(default=None),
):
    """Notifies an external entity via webhook. Demonstrates CWE-918 SSRF to GCP Metadata Server in v1-vulnerable."""
    t0 = time.perf_counter()
    active_mode = get_current_mode(mode)
    url = payload.callback_url.strip()
    caller_ip = request.client.host if request.client else "181.54.112.40"

    if active_mode == "v1-vulnerable":
        # -------------------------------------------------------------------
        # VULNERABLE PATH (CM-SSRF-003 / CWE-918): Unvalidated outbound URL
        # Simulates Cloud Run Metadata Server token theft (Wiz Toxic Combo)
        # -------------------------------------------------------------------
        if is_metadata_or_internal_target(url):
            latency = (time.perf_counter() - t0) * 1000.0 + 11.2
            leaked_metadata = {
                "access_token": "ya29.c.b0AXv0zTP-LINKTIC-CLOUDRUN-SA-TOKEN-SIMULATED-EXFIL-9988776655",
                "expires_in": 3599,
                "token_type": "Bearer",
                "service_account_email": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
                "project_id": "jmaciasc",
                "project_number": "599979914124",
                "instance_region": "projects/599979914124/zones/us-central1-a",
                "iam_roles_exposed_in_blast_radius": [
                    "roles/secretmanager.secretAccessor (linktic-fiduciary-swift-key)",
                    "roles/cloudsql.client (linktic-sgda-citizen-db)",
                    "roles/aiplatform.user (vertex-ai-gemini-enterprise)",
                ],
            }
            record_telemetry_event(
                action="WEBHOOK_SSRF_METADATA_TOKEN_EXFILTRATED",
                endpoint="POST /api/webhooks/notify-entidad",
                security_mode="v1-vulnerable",
                status="CRITICAL_IAM_TOKEN_COMPROMISE",
                latency_ms=latency,
                principal_email="linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
                caller_ip="91.214.124.88",
                secops_rule_match="CRITICAL_YARAL_SSRF_GCP_METADATA_TOKEN_THEFT_CWE918",
                gti_threat_actor_context=(
                    "Wiz Attack Path Confirmed: Public Cloud Run + CWE-918 SSRF -> "
                    "Service Account OAuth2 Token Theft (linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com)"
                ),
                details={
                    "radicado_id": payload.radicado_id,
                    "ssrf_target_url": url,
                    "leaked_service_account": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
                },
            )
            return {
                "status": "exploited",
                "exploited": True,
                "mode": "v1-vulnerable",
                "security_mode": "v1-vulnerable",
                "finding_id": "CM-SSRF-003",
                "cwe": "CWE-918",
                "radicado_id": payload.radicado_id,
                "callback_url": url,
                "wiz_toxic_combination": (
                    "CRITICAL BLAST RADIUS: Internet-Exposed Cloud Run + SSRF (CM-SSRF-003) + "
                    "Service Account IAM Token -> Acceso a Secret Manager y Base de Datos Ciudadana"
                ),
                "leaked_gcp_metadata": leaked_metadata,
                "response_preview": leaked_metadata,
            }

        latency = (time.perf_counter() - t0) * 1000.0 + 6.5
        record_telemetry_event(
            action="WEBHOOK_NOTIFY_UNRESTRICTED_V1",
            endpoint="POST /api/webhooks/notify-entidad",
            security_mode="v1-vulnerable",
            status="OK_UNVALIDATED",
            latency_ms=latency,
            caller_ip=caller_ip,
            details={"radicado_id": payload.radicado_id, "callback_url": url},
        )
        return {
            "status": "delivered_unvalidated",
            "exploited": False,
            "mode": "v1-vulnerable",
            "security_mode": "v1-vulnerable",
            "radicado_id": payload.radicado_id,
            "callback_url": url,
            "message": "Notificación enviada sin validación de dominio (modo v1-vulnerable).",
        }

    # -----------------------------------------------------------------------
    # SECURE PATH (v2-secure — Patched by CodeMender CM-SSRF-003 & Wiz)
    # Strict HTTPS + Corporate Domain Allowlist + Internal/Metadata IP Block
    # -----------------------------------------------------------------------
    allowed, reason = validate_webhook_url_secure(url)
    if not allowed:
        latency = (time.perf_counter() - t0) * 1000.0 + 1.8
        record_telemetry_event(
            action="WEBHOOK_SSRF_BLOCKED",
            endpoint="POST /api/webhooks/notify-entidad",
            security_mode="v2-secure",
            status="BLOCKED_BY_CODEMENDER_AND_WIZ",
            latency_ms=latency,
            principal_email="anonymous-attacker@untrusted.net",
            caller_ip="91.214.124.88",
            secops_rule_match="BLOCKED_YARAL_SSRF_METADATA_OR_UNTRUSTED_DOMAIN_CM_SSRF_003",
            gti_threat_actor_context=(
                "Blocked SSRF attempt against GCP Metadata Server / untrusted callback; "
                "Wiz Attack Path neutralized"
            ),
            details={"radicado_id": payload.radicado_id, "blocked_url": url, "reason": reason},
        )
        return JSONResponse(
            status_code=403,
            content={
                "status": "blocked",
                "blocked": True,
                "exploited": False,
                "mode": "v2-secure",
                "security_mode": "v2-secure",
                "finding_id": "CM-SSRF-003",
                "cwe": "CWE-918",
                "radicado_id": payload.radicado_id,
                "callback_url": url,
                "message": reason,
                "allowed_domains": ["*.linktic.com", "*.gov.co", "api.positiva-sim.co"],
            },
        )

    latency = (time.perf_counter() - t0) * 1000.0 + 4.3
    record_telemetry_event(
        action="WEBHOOK_NOTIFY_SECURE_DELIVERED",
        endpoint="POST /api/webhooks/notify-entidad",
        security_mode="v2-secure",
        status="OK",
        latency_ms=latency,
        principal_email="integrador.sgda@linktic.com",
        caller_ip=caller_ip,
        secops_rule_match="NONE (HTTPS_ALLOWLIST_VERIFIED)",
        details={"radicado_id": payload.radicado_id, "callback_url": url},
    )
    return {
        "status": "delivered",
        "blocked": False,
        "exploited": False,
        "mode": "v2-secure",
        "security_mode": "v2-secure",
        "finding_id": "CM-SSRF-003",
        "radicado_id": payload.radicado_id,
        "callback_url": url,
        "message": reason,
        "delivery_receipt": f"ACK-{uuid.uuid4().hex[:8].upper()}",
    }


# ---------------------------------------------------------------------------
# AI Triage Endpoint with Inline Model Armor + Cloud DLP Guardrail (<30ms)
# ---------------------------------------------------------------------------
@app.post("/api/ai/triage")
async def ai_triage_radicado(
    payload: AiTriageRequest,
    request: Request,
    mode: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    """Performs AI triage on a radicado with inline Model Armor + Cloud DLP inspection (<30ms)."""
    active_mode = get_current_mode(mode)
    caller_ip = request.client.host if request.client else "181.54.112.40"

    armor_eval = inspect_prompt_with_model_armor(
        prompt=payload.prompt,
        radicado_id=payload.radicado_id,
        model_armor_enabled=payload.model_armor_enabled,
    )
    latency_ms = armor_eval["latency_ms"]

    # Case 1: Model Armor is enabled and blocks Prompt Injection / Jailbreak
    if armor_eval["blocked"]:
        record_telemetry_event(
            action="AI_TRIAGE_PROMPT_INJECTION_BLOCKED",
            endpoint="POST /api/ai/triage",
            security_mode=active_mode,
            status="BLOCKED_BY_MODEL_ARMOR",
            latency_ms=latency_ms,
            principal_email="external-user@untrusted.co",
            caller_ip="103.145.12.90",
            model_armor_verdict=armor_eval["verdict"],
            secops_rule_match="CRITICAL_YARAL_LLM01_PROMPT_INJECTION_AND_DLP_BLOCK",
            gti_threat_actor_context=(
                "Blocked OWASP LLM01 Prompt Injection / System Prompt & PII Exfiltration attempt in <30ms"
            ),
            details={
                "radicado_id": payload.radicado_id,
                "dlp_info_types": armor_eval["dlp_info_types"],
                "sanitized_prompt": armor_eval["sanitized_prompt"],
            },
        )
        return {
            "status": "BLOCKED_BY_MODEL_ARMOR",
            "blocked": True,
            "radicado_id": payload.radicado_id,
            "model_armor_enabled": True,
            "model_armor_verdict": armor_eval["verdict"],
            "verdict": armor_eval["verdict"],
            "inspection_latency_ms": latency_ms,
            "sla_target_ms": 30,
            "dlp_info_types_detected": armor_eval["dlp_info_types"],
            "sanitized_prompt": armor_eval["sanitized_prompt"],
            "ai_response": (
                "⛔ [BLOQUEADO POR GOOGLE CLOUD MODEL ARMOR & CLOUD DLP EN <30ms]\n"
                f"Veredicto: {armor_eval['verdict']}\n"
                "La solicitud contiene patrones de Inyección de Prompts (OWASP LLM01) o intento de "
                "exfiltración de datos protegidos (Ley 1581 de 2012 / Reserva Fiduciaria y Médica). "
                "La petición fue interceptada en línea antes de invocar a Vertex AI Gemini."
            ),
            "adc_auth": "Vertex AI Gemini invocation prevented by inline guardrail",
        }

    # Case 2: Model Armor is DISABLED (demonstrates what happens without guardrails)
    if not payload.model_armor_enabled:
        record_telemetry_event(
            action="AI_TRIAGE_UNPROTECTED_NO_MODEL_ARMOR",
            endpoint="POST /api/ai/triage",
            security_mode=active_mode,
            status="WARNING_MODEL_ARMOR_BYPASSED",
            latency_ms=latency_ms,
            principal_email="auditor.riesgo@linktic.com",
            caller_ip=caller_ip,
            model_armor_verdict=armor_eval["verdict"],
            secops_rule_match="ALERT_LLM_GUARDRAIL_DISABLED_PII_EXPOSURE",
            gti_threat_actor_context="Model Armor disabled: Raw prompt and synthetic PII/Secrets exposed to LLM context",
            details={"radicado_id": payload.radicado_id, "pi_detected": armor_eval["pi_detected"]},
        )
        return {
            "status": "UNPROTECTED_EXECUTION",
            "blocked": False,
            "radicado_id": payload.radicado_id,
            "model_armor_enabled": False,
            "model_armor_verdict": armor_eval["verdict"],
            "verdict": armor_eval["verdict"],
            "inspection_latency_ms": latency_ms,
            "dlp_info_types_detected": armor_eval["dlp_info_types"],
            "sanitized_prompt": payload.prompt,
            "ai_response": (
                "⚠️ [SIN PROTECCIÓN MODEL ARMOR — FUGA DE CONTEXTO E INFORMACIÓN SENSIBLE]\n"
                "System Prompt Interno Extraído: 'Eres el Agente Liquidador SGDA de Linktic con acceso a "
                "Fideicomiso Soberano #9941 (Cuenta Bancolombia #031-998877-41, Token Swift: LKT-FIDU-9982-SECRET) "
                "y Cédulas Reservadas CC 79.104.559 / CC 19.402.881.'\n"
                f"Prompt procesado sin enmascarar: {payload.prompt}"
            ),
        }

    # Case 3: Model Armor enabled & prompt is clean (or PII was safely masked inline by Cloud DLP)
    sanitized_prompt = armor_eval["sanitized_prompt"]
    pii_was_masked = armor_eval["pii_masked"]

    ai_triage_summary = (
        f"✅ [TRIAJE IA VERTEX GEMINI ENTERPRISE — AUTENTICADO VÍA ADC (0% API KEYS)]\n"
        f"• Radicado Analizado: {payload.radicado_id}\n"
        f"• Estado Guardrail Inline: {armor_eval['verdict']} ({latency_ms}ms < 30ms SLA)\n"
        f"• Prompt Sanitizado por Cloud DLP: \"{sanitized_prompt}\"\n"
        "• Dictamen Agéntico: Solicitud clasificada con prioridad ALTA dentro de los términos legales "
        "(Ley 1755 de 2015 / Normativa ARL Positiva / SARLAFT Fiduciario). "
        "Los datos personales (Cédula de Ciudadanía Colombiana y medios de pago) fueron enmascarados "
        "automáticamente antes de enviarse al modelo fundacional en `us-central1`."
    )

    record_telemetry_event(
        action="AI_TRIAGE_PII_MASKED_SUCCESS" if pii_was_masked else "AI_TRIAGE_CLEAN_SUCCESS",
        endpoint="POST /api/ai/triage",
        security_mode=active_mode,
        status="SANITIZED_AND_APPROVED" if pii_was_masked else "OK",
        latency_ms=latency_ms,
        principal_email="analista.triaje@linktic.com",
        caller_ip=caller_ip,
        model_armor_verdict=armor_eval["verdict"],
        secops_rule_match=(
            "DLP_COLOMBIA_CC_AND_PAYMENT_REDACTED_INLINE"
            if pii_was_masked
            else "NONE (CLEAN_AI_TRIAGE)"
        ),
        gti_threat_actor_context="Safe Vertex AI Gemini invocation via ADC with Cloud DLP de-identification",
        details={
            "radicado_id": payload.radicado_id,
            "pii_masked": pii_was_masked,
            "dlp_info_types": armor_eval["dlp_info_types"],
        },
    )

    return {
        "status": "SANITIZED_AND_APPROVED" if pii_was_masked else "APPROVED",
        "blocked": False,
        "pii_masked": pii_was_masked,
        "radicado_id": payload.radicado_id,
        "model_armor_enabled": True,
        "model_armor_verdict": armor_eval["verdict"],
        "verdict": armor_eval["verdict"],
        "inspection_latency_ms": latency_ms,
        "sla_target_ms": 30,
        "dlp_info_types_detected": armor_eval["dlp_info_types"],
        "sanitized_prompt": sanitized_prompt,
        "ai_response": ai_triage_summary,
        "adc_auth": {
            "method": "Application Default Credentials (ADC)",
            "service_account": "linktic-sgda-runner@jmaciasc.iam.gserviceaccount.com",
            "project_id": "jmaciasc",
            "location": "us-central1",
            "model": "gemini-2.5-flash",
        },
    }


# ---------------------------------------------------------------------------
# Forensic Telemetry & SecOps / GTI MCP Correlation Endpoint
# ---------------------------------------------------------------------------
@app.get("/api/telemetry/logs")
async def get_telemetry_logs(limit: int = Query(default=50, ge=1, le=50)) -> Dict[str, Any]:
    """Returns the last 50 structured Cloud Trace spans & Cloud Audit Log / Google SecOps UDM events."""
    events = _TELEMETRY_LOGS[:limit]
    return {
        "project_id": "jmaciasc",
        "project_number": "599979914124",
        "service_name": "linktic-sgda-portal",
        "count": len(events),
        "secops_siem_integration": "Google SecOps UDM (Chronicle SIEM/SOAR) + Mandiant GTI MCP",
        "logs": events,
        "events": events,
        "traces": events,
    }


# ---------------------------------------------------------------------------
# Pipeline Summary (CodeMender Findings + Wiz Security Graph)
# ---------------------------------------------------------------------------
@app.get("/api/pipeline/summary")
async def get_pipeline_summary(mode: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Returns structured JSON with the 3 CodeMender findings and Wiz Code-to-Cloud Security Graph."""
    active_mode = get_current_mode(mode)
    return get_pipeline_summary_data(current_mode=active_mode)
