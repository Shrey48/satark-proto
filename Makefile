.PHONY: dev up down seed-taxonomy seed-gkg build test

dev:
	docker compose -f docker-compose.dev.yml up -d
	@echo "Dev stack running. API: http://localhost:8000 Dashboard: http://localhost:3000"

up:
	docker compose up -d

down:
	docker compose down

seed-taxonomy:
	cd apps/api && poetry run python -m scripts.seed.seed_taxonomy

seed-gkg:
	cd apps/api && poetry run python -m scripts.seed.seed_gkg

create-tenant:
	cd apps/api && poetry run python -m scripts.dev.create_tenant $(TENANT)

test:
	cd apps/api && poetry run pytest tests/ -v

build:
	docker compose build
