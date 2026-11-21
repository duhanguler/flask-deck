# Contributing to flask-deck

Thank you for your interest in contributing to `flask-deck`!

## Development Setup

```bash
git clone https://github.com/duhanguler/flask-deck.git
cd flask-deck
uv sync --extra dev
```

## Quality Gates

Before opening a pull request, ensure all checks pass:

```bash
uv run ruff check src tests examples benchmarks
uv run mypy src
uv run pytest --cov=flask_deck --cov-report=term-missing
uv run python benchmarks/bench_deck.py
```

## Design & Engineering Standards

1. **Zero Node Build / Zero CDN:** All CSS and JS live under `src/flask_deck/static/` and must stay within the `< 12 KB` gzipped budget.
2. **Strict CSP Compliance:** Never introduce inline `style="..."` or inline event handlers (`onclick=`, etc.) in templates or formatters, and never use `innerHTML` with untrusted strings in `deck.js`.
3. **No N+1 Regressions:** List views must eager-load displayed relationships and pass the SQL query budget assertions in `tests/test_query_filters_n1.py`.
4. **Fail-Closed Security:** Every new route or API endpoint must enforce CSRF (for mutations), RBAC permissions, `scope_query`, and `read_only` guards.
