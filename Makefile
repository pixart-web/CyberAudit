.PHONY: setup up down restart logs migrate seed test lint format clean worker worker-logs test-worker seed-jobs adapters-health purge-demo-jobs seed-phase3 seed-phase4 test-adapters test-network-safety test-discovery test-graph test-vulnerability-intelligence test-risk lab-services-up lab-services-down lab-network-up lab-network-down import-demo-results purge-evidence retest-demo sync-vulnerability-feeds recalculate-risk refresh-attack-paths coverage-report

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

lab-services-up:
	docker compose --profile lab up -d lab-http lab-tls

lab-services-down:
	docker compose --profile lab stop lab-http lab-tls

lab-network-up:
	docker compose --profile lab up -d lab-http lab-tls lab-banners

lab-network-down:
	docker compose --profile lab stop lab-http lab-tls lab-banners

sync-vulnerability-feeds:
	docker compose exec api python -m cyberaudit.phase4_tasks sync-feeds

recalculate-risk:
	docker compose exec api python -m cyberaudit.phase4_tasks recalculate-risk

refresh-attack-paths:
	docker compose exec api python -m cyberaudit.phase4_tasks refresh-attack-paths

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
