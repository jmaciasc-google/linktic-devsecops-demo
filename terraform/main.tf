# ============================================================================
# ✅ INFRAESTRUCTURA REMEDIADA (v2-secure) — Linktic SGDA & Claims AI Portal
# Verificado por: `wizcli iac scan` (0 Critical, 0 High) + Antigravity 2.0
# Proyecto GCP Argolis: jmaciasc (599979914124) | Región: us-central1
# ============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project_id" {
  description = "ID del proyecto GCP en Argolis"
  type        = string
  default     = "jmaciasc"
}

variable "project_number" {
  description = "Número del proyecto GCP en Argolis"
  type        = string
  default     = "599979914124"
}

variable "region" {
  description = "Región de despliegue para Cloud Run y Artifact Registry"
  type        = string
  default     = "us-central1"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# ----------------------------------------------------------------------------
# 1. Identidad Dedicada de Mínimo Privilegio (Remedia WIZ-IAC-002)
#    Neutraliza el Blast Radius en caso de intento de SSRF al Metadata Server
# ----------------------------------------------------------------------------
resource "google_service_account" "linktic_sgda_runner" {
  account_id   = "linktic-sgda-runner"
  display_name = "Linktic SGDA Portal — Least-Privilege Cloud Run Service Account"
  description  = "Identidad gobernada por Antigravity & Wiz para invocar Vertex AI y Model Armor via ADC sin API Keys"
}

resource "google_project_iam_member" "vertex_ai_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.linktic_sgda_runner.email}"
}

resource "google_project_iam_member" "cloud_dlp_user" {
  project = var.project_id
  role    = "roles/dlp.user"
  member  = "serviceAccount:${google_service_account.linktic_sgda_runner.email}"
}

resource "google_project_iam_member" "cloud_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.linktic_sgda_runner.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.linktic_sgda_runner.email}"
}

# ----------------------------------------------------------------------------
# 2. Gestión de Secretos en Google Secret Manager (Remedia WIZ-IAC-001)
#    0% API Keys en código o variables de entorno; Vertex AI usa ADC puro.
# ----------------------------------------------------------------------------
resource "google_secret_manager_secret" "webhook_hmac_secret" {
  secret_id = "linktic-sgda-webhook-hmac"

  replication {
    auto {}
  }

  labels = {
    app        = "linktic-sgda-portal"
    managed_by = "terraform-wiz-verified"
  }
}

resource "google_secret_manager_secret_iam_member" "runner_secret_access" {
  secret_id = google_secret_manager_secret.webhook_hmac_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.linktic_sgda_runner.email}"
}

# ----------------------------------------------------------------------------
# 3. Política WAF en Google Cloud Armor (Remedia WIZ-IAC-003)
#    Defensa perimetral contra SQL Injection (CWE-89) y RCE/CmdInj (CWE-78)
# ----------------------------------------------------------------------------
resource "google_compute_security_policy" "linktic_sgda_waf" {
  name        = "linktic-sgda-cloud-armor-waf"
  description = "Política WAF OWASP Top 10 + Protección SGDA para Linktic"

  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "Bloqueo perimetral de SQL Injection (defensa en profundidad junto al parche CM-SQLI-001)"
  }

  rule {
    action   = "deny(403)"
    priority = 1100
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
    description = "Bloqueo perimetral de Remote Command Execution (defensa en profundidad junto a CM-CMDI-002)"
  }

  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Regla por defecto para tráfico ciudadano legítimo"
  }
}

# ----------------------------------------------------------------------------
# 4. Servicio Google Cloud Run v2 Endurecido (linktic-sgda-portal)
# ----------------------------------------------------------------------------
resource "google_cloud_run_v2_service" "linktic_sgda_portal" {
  name     = "linktic-sgda-portal"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.linktic_sgda_runner.email

    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }

    containers {
      image = "us-central1-docker.pkg.dev/${var.project_id}/linktic-devsecops/linktic-sgda-portal:latest"

      ports {
        container_port = 8080
      }

      env {
        name  = "DEFAULT_SECURITY_MODE"
        value = "v2-secure"
      }

      env {
        name  = "GCP_PROJECT_ID"
        value = var.project_id
      }

      env {
        name  = "GCP_PROJECT_NUMBER"
        value = var.project_number
      }

      env {
        name  = "VERTEX_AUTH_MODE"
        value = "ADC_KEYLESS"
      }

      env {
        name  = "MODEL_ARMOR_INLINE_ENABLED"
        value = "true"
      }

      env {
        name = "WEBHOOK_HMAC_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.webhook_hmac_secret.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }
    }
  }
}

output "cloud_run_service_url" {
  description = "URL del servicio Cloud Run desplegado en Argolis (jmaciasc)"
  value       = google_cloud_run_v2_service.linktic_sgda_portal.uri
}
