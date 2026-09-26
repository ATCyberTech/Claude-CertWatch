.PHONY: install dev-install run test lint typecheck check fmt

install:
	pip install -e .

dev-install:
	pip install -e ".[dev]"

run:
	uvicorn app.main:app --reload --port 8000

test:
	pytest -v

lint:
	ruff check .

fmt:
	ruff format .

typecheck:
	mypy app

# Runs everything CI runs, in the same order, so a local pass predicts a green CI run.
check: lint typecheck test
