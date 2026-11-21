.PHONY: install test cov lint typecheck bench build demo check

install:
	uv sync --extra dev

test:
	uv run pytest

cov:
	uv run pytest --cov=flask_deck --cov-report=term-missing

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
