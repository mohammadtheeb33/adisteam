# ADIS developer tasks (GNU make).
#
# Without make (e.g. stock Windows), run the underlying commands directly;
# see docs/DEVELOPMENT.md for the equivalents.

.DEFAULT_GOAL := help

PYTHON  ?= python
VENV    ?= .venv
COMPOSE ?= docker compose

ifeq ($(OS),Windows_NT)
PY := $(VENV)/Scripts/python.exe
else
PY := $(VENV)/bin/python
endif

.PHONY: help venv install lint format typecheck test test-unit test-integration coverage \
        check compose-config infra-up infra-down infra-logs db-upgrade db-downgrade \
        db-revision db-current kafka-up kafka-topics schemas api agent agent-simulate \
        agent-status normalizer test-infra-up test-infra-down supabase-test-up app-up \
        app-down test-e2e verify-phase1 clean

help: ## List available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

$(PY):
	$(PYTHON) -m venv $(VENV)

venv: $(PY) ## Create the local virtual environment (.venv)

install: $(PY) ## Install the workspace (editable) with dev tooling
	$(PY) -m pip install --upgrade "pip>=25.1"
	$(PY) -m pip install --editable . --group dev

lint: ## Run ruff lint and format checks
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

format: ## Apply ruff fixes and formatting
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

typecheck: ## Run mypy (strict)
	$(PY) -m mypy

test: ## Run the full test suite
	$(PY) -m pytest

test-unit: ## Run unit tests only (no external services)
	$(PY) -m pytest tests/unit

test-integration: ## Run integration tests (TEST_DATABASE_URL, TEST_KAFKA_BOOTSTRAP_SERVERS, TEST_REDIS_URL)
	$(PY) -m pytest tests/integration

test-infra-up: ## Start the disposable test broker, database and Redis (compose profile "test")
	$(COMPOSE) --profile test up -d --wait kafka postgres-test redis

test-infra-down: ## Stop and remove the test databases (volumes are kept)
	$(COMPOSE) --profile test --profile supabase-test rm --stop --force postgres-test supabase-db-test

supabase-test-up: ## Start the disposable Supabase Postgres (compose profile "supabase-test")
	$(COMPOSE) --profile supabase-test up -d --wait supabase-db-test

app-up: ## Build and start the api and normalizer (compose profile "app")
	$(COMPOSE) --profile app up -d --build --wait api normalizer

app-down: ## Stop the api and normalizer containers
	$(COMPOSE) --profile app stop api normalizer

test-e2e: ## Run the end-to-end tests (TEST_E2E=1; stops and restarts the test containers)
	$(PY) -m pytest tests/e2e

verify-phase1: ## Run the Phase 1 verification and write docs/PHASE1_VERIFICATION_REPORT.md
	$(PY) -m tests.e2e.phase1 --report docs/PHASE1_VERIFICATION_REPORT.md

coverage: ## Run tests with a coverage report
	$(PY) -m pytest --cov --cov-report=term-missing

check: lint typecheck test compose-config ## Run all validation

compose-config: ## Validate docker-compose.yml against .env
	$(COMPOSE) config --quiet

infra-up: ## Start local infrastructure and wait until healthy
	$(COMPOSE) up -d --wait

infra-down: ## Stop local infrastructure (volumes are kept)
	$(COMPOSE) down

infra-logs: ## Follow local infrastructure logs
	$(COMPOSE) logs -f --tail=100

db-upgrade: ## Apply all database migrations
	$(PY) -m alembic upgrade head

db-downgrade: ## Revert the most recent database migration
	$(PY) -m alembic downgrade -1

db-revision: ## Autogenerate a migration: make db-revision m="add hosts table"
	$(PY) -m alembic revision --autogenerate -m "$(m)"

db-current: ## Show the database's current migration revision
	$(PY) -m alembic current

kafka-up: ## Start only the local Kafka broker and wait until healthy
	$(COMPOSE) up -d --wait kafka

kafka-topics: ## Create missing ADIS Kafka topics (idempotent)
	$(PY) scripts/kafka_create_topics.py

schemas: ## Regenerate the committed canonical event JSON Schemas
	$(PY) scripts/generate_event_schemas.py

api: ## Run the ingestion API (needs .env with API_INGEST_TOKENS and a reachable Kafka)
	$(PY) -m apps.api

agent: ## Run the endpoint agent (needs AGENT_TOKEN matching an API_INGEST_TOKENS entry)
	$(PY) -m apps.agent run

agent-simulate: ## Run the agent with synthetic auth and flow telemetry (development only)
	$(PY) -m apps.agent simulate

agent-status: ## Show the agent's identity, queue, quarantine and registration state
	$(PY) -m apps.agent status

normalizer: ## Run the normalization pipeline (needs Kafka topics and a migrated database)
	$(PY) -m apps.normalizer

clean: ## Remove caches and build artifacts
	$(PYTHON) -c "import pathlib, shutil; root = pathlib.Path('.'); [shutil.rmtree(p, ignore_errors=True) for pat in ('.pytest_cache', '.mypy_cache', '.ruff_cache', 'htmlcov', 'build', 'dist', '*.egg-info', '**/__pycache__') for p in root.glob(pat) if '.venv' not in p.parts]; (root / '.coverage').unlink(missing_ok=True)"
