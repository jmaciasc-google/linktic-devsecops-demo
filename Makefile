.PHONY: help verify test run-local pipeline-live cm-scan wiz-scan deploy-argolis cloudbuild tutorial

PROJECT_ID ?= jmaciasc
REGION ?= us-central1
SERVICE_NAME ?= linktic-sgda-portal
PORT ?= 8080

help: ## Muestra los comandos disponibles para la Demo DevSecOps de Linktic
	@echo "=========================================================================="
	@echo " 🛡️  Linktic End-to-End Agentic DevSecOps Pipeline Demo — Comandos Make"
	@echo "=========================================================================="
	@echo "  make pipeline-live   Recorrido interactivo paso a paso (Etapas 1→6: Dev -> Wiz -> CodeMender -> Cloud Run)"
	@echo "  make verify          Ejecuta el verificador Pre-Flight de 10 puntos"
	@echo "  make test            Ejecuta la suite de pruebas Pytest (v1-vulnerable vs v2-secure)"
	@echo "  make run-local       Inicia el servidor FastAPI localmente en el puerto $(PORT)"
	@echo "  make cm-scan         Ejecuta el flujo completo de CodeMender (find, verify, fix, report)"
	@echo "  make wiz-scan        Ejecuta Wiz CLI (IaC, secretos, contenedor) y Triage Code-to-Cloud"
	@echo "  make deploy-argolis  Despliega el servicio en vivo en Cloud Run (Proyecto: $(PROJECT_ID))"
	@echo "  make cloudbuild      Ejecuta el pipeline CI/CD de 6 etapas en Google Cloud Build"
	@echo "  make tutorial        Abre el tutorial interactivo nativo en Google Cloud Shell"
	@echo "=========================================================================="

pipeline-live: ## Ejecuta el recorrido cronológico interactivo de 6 etapas en la terminal
	bash scripts/walkthrough_pipeline_live.sh

verify: ## Ejecuta el verificador automatizado de 10 puntos
	python3 scripts/verify_demo_readiness.py

test: ## Ejecuta las pruebas unitarias y de seguridad con pytest
	python3 -m pytest tests/test_app_and_security.py -v

run-local: ## Levanta la aplicación localmente en http://localhost:8080
	python3 -m uvicorn backend.app:app --host 0.0.0.0 --port $(PORT) --reload

cm-scan: ## Ejecuta CodeMender (find -> verify -> fix -> report)
	bash scripts/demo_cli_runner.sh cm-find
	bash scripts/demo_cli_runner.sh cm-verify
	bash scripts/demo_cli_runner.sh cm-fix
	bash scripts/demo_cli_runner.sh cm-report

wiz-scan: ## Ejecuta Wiz CLI (IaC, directorio, contenedor) y el skill Code-to-Cloud Triage
	bash scripts/demo_cli_runner.sh wiz-iac-scan
	bash scripts/demo_cli_runner.sh wiz-dir-scan
	bash scripts/demo_cli_runner.sh wiz-docker-scan
	bash scripts/demo_cli_runner.sh cm-wiz-triage

deploy-argolis: ## Configura y despliega el portal en Cloud Run dentro del proyecto Argolis (jmaciasc)
	bash scripts/setup_argolis.sh

cloudbuild: ## Dispara el pipeline CI/CD completo en Google Cloud Build (proyecto jmaciasc)
	gcloud builds submit --config=cloudbuild.yaml --project=$(PROJECT_ID) .

tutorial: ## Lanza el tutorial interactivo en Google Cloud Shell
	@if command -v cloudshell >/dev/null 2>&1; then \
		cloudshell launch-tutorial tutorial.md; \
	elif command -v teachme >/dev/null 2>&1; then \
		teachme tutorial.md; \
	else \
		echo "ℹ️  Para abrir el panel interactivo dentro de Google Cloud Shell ejecuta:"; \
		echo "    cloudshell launch-tutorial tutorial.md"; \
	fi
