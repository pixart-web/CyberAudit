.PHONY: setup up down restart logs migrate seed test lint format clean worker worker-logs test-worker seed-jobs adapters-health purge-demo-jobs seed-phase3 seed-phase4 seed-phase5 seed-enterprise seed-hardening enterprise-domain-seed enterprise-domain-test enterprise-domain-sync-demo enterprise-domain-health identity-test cloud-test kubernetes-test zero-trust-test test-adapters test-network-safety test-discovery test-graph test-vulnerability-intelligence test-risk test-appsec test-soc test-grc test-ai test-enterprise test-hardening test-production-readiness test-rls verify-production-config backup restore-drill load-smoke readiness-environment-check readiness-tools-verify readiness-up readiness-down readiness-keycloak readiness-vault readiness-minio readiness-kind readiness-oidc-test readiness-webauthn-test readiness-rls-test readiness-cross-tenant-test readiness-dlq-test readiness-runner-test readiness-providers-test readiness-collect readiness-backup readiness-restore readiness-ha-test readiness-dr-test readiness-sbom readiness-scan readiness-provenance readiness-sign readiness-verify-signatures readiness-load-test readiness-coverage readiness-evidence readiness-gate release-candidate test-web-inventory test-api-security test-dependencies test-sca test-secrets test-sast test-iac test-containers test-cicd test-security-gates lab-services-up lab-services-down lab-network-up lab-network-down appsec-lab-up appsec-lab-down appsec-lab-down import-demo-results import-demo-api-spec generate-demo-sbom purge-evidence purge-appsec-demo retest-demo sync-vulnerability-feeds recalculate-risk rebuild-appsec-scores refresh-attack-paths rebuild-knowledge-graph coverage-report benchmark-appsec

setup:
	cp -n .env.example .env || true
	pnpm install
	python3.12 -m venv .venv
	.venv/bin/pip install -e "apps/api[dev]"

up:
	docker compose up --build -d

down:
	docker compose down

restart: down up

logs:
	docker compose logs -f

migrate:
	docker compose exec api alembic upgrade head

seed:
	docker compose exec api python -m cyberaudit.seed

seed-jobs:
	docker compose exec api python -m cyberaudit.seed_jobs

seed-phase3:
	docker compose exec api python -m cyberaudit.seed_phase3

seed-phase4:
	docker compose exec api python -m cyberaudit.seed_phase4

seed-phase5:
	docker compose exec api python -m cyberaudit.seed_phase5

seed-enterprise:
	docker compose exec api python -m cyberaudit.seed_enterprise

seed-hardening:
	docker compose exec api python -m cyberaudit.seed_hardening

test-hardening:
	.venv/bin/pytest apps/api/tests/test_product_hardening.py

test-production-readiness:
	.venv/bin/pytest apps/api/tests/test_production_readiness_closure.py

test-rls:
	.venv/bin/pytest apps/api/tests/test_postgresql_rls_integration.py

verify-production-config:
	.venv/bin/python infrastructure/scripts/verify_production_config.py

backup:
	infrastructure/scripts/backup_postgres.sh

restore-drill:
	infrastructure/scripts/restore_drill.sh

load-smoke:
	.venv/bin/python infrastructure/testing/load_smoke.py

readiness-environment-check:
	scripts/readiness/check-environment.sh

readiness-tools-verify:
	scripts/readiness/verify-tools.sh

readiness-up:
	scripts/readiness/start-production-like.sh

readiness-down:
	scripts/readiness/stop-production-like.sh

readiness-keycloak:
	docker-compose --env-file infrastructure/readiness/runtime/readiness.env -f infrastructure/readiness/compose.production-like.yml up -d keycloak keycloak-proxy

readiness-vault:
	scripts/readiness/bootstrap-vault.sh

readiness-minio:
	scripts/readiness/bootstrap-minio.sh

readiness-kind:
	scripts/readiness/create-kind-cluster.sh

readiness-oidc-test:
	scripts/readiness/validate-oidc-browser.sh

readiness-webauthn-test:
	scripts/readiness/validate-webauthn-browser.sh

readiness-rls-test:
	scripts/readiness/validate-rls.sh

readiness-cross-tenant-test:
	scripts/readiness/validate-cross-tenant.sh

readiness-dlq-test:
	scripts/readiness/validate-dlq.sh

readiness-runner-test:
	scripts/readiness/validate-docker-runner.sh
	scripts/readiness/create-kind-cluster.sh
	scripts/readiness/validate-kubernetes-runner.sh

readiness-providers-test:
	scripts/readiness/validate-providers.sh

readiness-collect:
	scripts/readiness/collect-runtime-evidence.sh

readiness-backup:
	scripts/readiness/backup-production-like.sh

readiness-restore:
	scripts/readiness/restore-production-like.sh

readiness-ha-test:
	scripts/readiness/validate-ha.sh

readiness-dr-test:
	scripts/readiness/validate-dr.sh

readiness-sbom:
	scripts/readiness/generate-sbom.sh

readiness-scan:
	scripts/readiness/scan-release.sh

readiness-provenance:
	scripts/readiness/generate-provenance.sh

readiness-sign:
	scripts/readiness/sign-release-artifacts.sh

readiness-verify-signatures:
	scripts/readiness/verify-release-signatures.sh

readiness-load-test:
	scripts/readiness/run-load-test.sh

readiness-coverage:
	scripts/readiness/collect-coverage.sh

readiness-evidence:
	scripts/readiness/build-evidence-manifest.py

readiness-gate:
	PYTHONPATH=apps/api .venv/bin/python scripts/readiness/evaluate-gate.py

release-candidate:
	scripts/readiness/release-candidate.sh

enterprise-domain-seed:
	docker compose exec api python -m cyberaudit.seed_domain_expansion

enterprise-domain-test:
	.venv/bin/pytest apps/api/tests/test_domain_expansion_services.py apps/api/tests/test_domain_expansion_routes.py

identity-test cloud-test kubernetes-test zero-trust-test:
	.venv/bin/pytest apps/api/tests/test_domain_expansion_services.py apps/api/tests/test_domain_expansion_routes.py

enterprise-domain-sync-demo:
	@echo "Queue a synthetic connector from Enterprise Connectors; external provider I/O is disabled."

enterprise-domain-health:
	@echo "GET /api/v1/enterprise/health with an authenticated system_health.read token."

worker:
	docker compose up --build worker

worker-logs:
	docker compose logs -f worker

test-worker:
	.venv/bin/pytest apps/api/tests/test_worker.py apps/api/tests/test_orchestrator.py

adapters-health:
	curl -fsS -X POST http://localhost:8000/api/v1/adapters/cyberaudit.demo_assessment/health-check

test-adapters:
	.venv/bin/pytest apps/api/tests/test_adapters.py apps/api/tests/test_phase3_adapters.py

test-network-safety:
	.venv/bin/pytest apps/api/tests/test_network_security.py apps/api/tests/test_evidence_imports.py

test-discovery:
	.venv/bin/pytest apps/api/tests/test_discovery.py apps/api/tests/test_phase4_adapters.py

test-graph:
	.venv/bin/pytest apps/api/tests/test_asset_graph.py

test-vulnerability-intelligence:
	.venv/bin/pytest apps/api/tests/test_vulnerability_intelligence.py

test-risk:
	.venv/bin/pytest apps/api/tests/test_risk_engine.py

test-appsec:
	.venv/bin/pytest apps/api/tests/test_appsec_services.py apps/api/tests/test_phase5_adapters.py apps/api/tests/test_phase5_routes.py

test-soc:
	.venv/bin/pytest apps/api/tests/test_enterprise_soc.py

test-grc:
	.venv/bin/pytest apps/api/tests/test_enterprise_grc.py

test-ai:
	.venv/bin/pytest apps/api/tests/test_enterprise_ai.py

test-enterprise:
	.venv/bin/pytest apps/api/tests/test_enterprise_soc.py apps/api/tests/test_enterprise_grc.py apps/api/tests/test_enterprise_ai.py apps/api/tests/test_enterprise_routes.py

test-web-inventory test-api-security test-dependencies test-sca test-secrets test-sast test-iac test-containers test-cicd test-security-gates:
	.venv/bin/pytest apps/api/tests/test_appsec_services.py apps/api/tests/test_phase5_adapters.py

lab-services-up:
	docker compose --profile lab up -d lab-http lab-tls

lab-services-down:
	docker compose --profile lab stop lab-http lab-tls

lab-network-up:
	docker compose --profile lab up -d lab-http lab-tls lab-banners

lab-network-down:
	docker compose --profile lab stop lab-http lab-tls lab-banners

appsec-lab-up:
	docker compose --profile appsec-lab up -d appsec-lab

appsec-lab-down:
	docker compose --profile appsec-lab stop appsec-lab

sync-vulnerability-feeds:
	docker compose exec api python -m cyberaudit.phase4_tasks sync-feeds

recalculate-risk:
	docker compose exec api python -m cyberaudit.phase4_tasks recalculate-risk

refresh-attack-paths:
	docker compose exec api python -m cyberaudit.phase4_tasks refresh-attack-paths

rebuild-knowledge-graph:
	@echo "Use the tenant-bound cyberaudit.enterprise_worker actor; direct cross-tenant rebuilds are disabled."

rebuild-appsec-scores:
	@echo "Use GET /api/v1/appsec/risk to inspect the versioned deterministic score."

generate-demo-sbom:
	@echo "Synthetic CycloneDX fixture: infrastructure/appsec-lab/sbom.json"

import-demo-api-spec:
	@echo "Import infrastructure/appsec-lab/openapi.json in API Specifications; preview is mandatory."

purge-appsec-demo:
	@echo "Direct purge is disabled; use audited retention workflows."

benchmark-appsec:
	.venv/bin/pytest -q apps/api/tests/test_appsec_services.py

coverage-report:
	.venv/bin/pytest --cov=cyberaudit --cov-report=term-missing --cov-report=html apps/api

import-demo-results:
	@echo "Use Importar Resultados na interface; confirmação exige preview e autorização."

purge-evidence:
	@echo "Use a política de retenção auditada; eliminação direta de evidências está desativada."

retest-demo:
	@echo "Abra um finding e selecione Solicitar reteste; o scope será revalidado."

purge-demo-jobs:
	@echo "Use the audited administration API; destructive direct purge is intentionally disabled."

test:
	pnpm test
	.venv/bin/pytest apps/api

lint:
	pnpm lint
	.venv/bin/ruff check apps/api
	.venv/bin/black --check apps/api
	.venv/bin/mypy apps/api/cyberaudit

format:
	pnpm format
	.venv/bin/ruff check --fix apps/api
	.venv/bin/black apps/api

clean:
	docker compose down -v
	find . -type d -name __pycache__ -prune -exec rm -r {} +
	find . -type d -name .pytest_cache -prune -exec rm -r {} +
