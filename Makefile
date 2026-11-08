.PHONY: install test lint format typecheck security iac-scan run docker-up docker-up-build docker-down docker-build-production migrate docker-migrate docker-seed-demo frontend-install frontend-dev frontend-build frontend-lint

install:
	python -m pip install -e '.[dev,security]'

test:
	python -m pytest

lint:
	python -m ruff check .

format:
	python -m ruff format .

typecheck:
	python -m mypy

security:
	python -m bandit -r backend/app backend/migrations scanner-engine policy-engine
	python -m pip_audit --strict .
	semgrep scan --error --config .semgrep.yml backend scanner-engine policy-engine reporting-engine

iac-scan:
	trivy config --severity HIGH,CRITICAL --exit-code 1 .

run:
	python -m uvicorn app.main:app --app-dir backend --host "$${CLOUDSENTINEL_API_HOST:-127.0.0.1}" --port "$${CLOUDSENTINEL_API_PORT:-8000}" --reload

docker-up:
	docker compose -f docker-compose.yml up

docker-up-build:
	docker compose -f docker-compose.yml up --build

docker-down:
	docker compose -f docker-compose.yml down

docker-build-production:
	docker build -f infrastructure/docker/Dockerfile.production -t cloudsentinel/backend:local .
	docker build -f infrastructure/docker/frontend/Dockerfile.production -t cloudsentinel/frontend:local .

migrate:
	python -m alembic upgrade head

docker-migrate:
	docker compose -f docker-compose.yml run --build --rm backend python -m alembic upgrade head

docker-seed-demo:
	@test -n "$(ORG_SLUG)" -a -n "$(ADMIN_EMAIL)" || (echo "Usage: make docker-seed-demo ORG_SLUG=... ADMIN_EMAIL=..." >&2; exit 2)
	docker compose -f docker-compose.yml exec backend python -m app.seed_demo_cli --organization-slug "$(ORG_SLUG)" --admin-email "$(ADMIN_EMAIL)"

frontend-install:
	cd frontend/cloudsentinel-ui && npm ci

frontend-dev:
	cd frontend/cloudsentinel-ui && npm run dev

frontend-build:
	cd frontend/cloudsentinel-ui && npm run build

frontend-lint:
	cd frontend/cloudsentinel-ui && npm run lint
