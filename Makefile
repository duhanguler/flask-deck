.PHONY: install test test-integration test-e2e cov lint typecheck bench build demo check

install:
	uv sync --extra dev

test:
	uv run pytest -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning

test-integration:
	uv run pytest -m "postgres or redis" -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning

test-e2e:
	uv run pytest -m e2e

cov:
	uv run pytest -W error::ResourceWarning -W error::pytest.PytestUnraisableExceptionWarning --cov=flask_deck --cov-report=term-missing

lint:
	uv run ruff check src tests examples benchmarks

typecheck:
	uv run mypy src

bench:
	uv run python benchmarks/bench_deck.py

build:
	uv build

demo:
	uv run flask-deck demo --port 5055

check: lint typecheck cov bench
