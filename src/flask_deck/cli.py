from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from typing import Any

import click
from flask import current_app
from flask.cli import AppGroup, with_appcontext

from flask_deck._version import __version__
from flask_deck.deck import Deck, run_security_audit

deck_cli = AppGroup("deck", help="Flask-Deck admin workbench commands.")


def _get_registered_decks() -> dict[str, Deck]:
    decks: dict[str, Deck] = current_app.extensions.get("flask_deck", {})
    return decks


@deck_cli.command("info")
@with_appcontext
def cli_info() -> None:
    """List registered Flask-Deck instances, models, columns, and security settings."""
    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.")
        return
    for name, deck in decks.items():
        click.echo(
            f"Deck '{name}' | prefix={deck.config.url_prefix} | env={deck.config.environment} "
            f"| auth={deck.auth.__class__.__name__} | read_only={deck.config.read_only}"
        )
        for slug, view in deck.views.items():
            click.echo(
                f"  - /{slug}/ ({view.meta.name}) "
                f"cols={len(view.list_columns)} search={list(view.resolved_searchable)} "
                f"tabs={len(view.quick_tabs)} actions={list(view.actions.keys())}"
            )


def _findings_to_sarif(all_results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    rules_seen: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in all_results:
        cat = str(item.get("category", "security"))
        sev = str(item.get("severity", "INFO"))
        rule_id = f"flask-deck/{cat}/{sev.lower()}"
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f"FlaskDeck{cat.capitalize()}{sev.capitalize()}",
                "shortDescription": {"text": f"Flask-Deck {cat} ({sev}) check"},
            }
        level = "error" if sev in {"CRITICAL", "HIGH"} else ("warning" if sev == "WARN" else "note")
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"[{item.get('deck', 'deck')}] {item.get('message', '')}"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "flask-deck",
                        "version": __version__,
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


@deck_cli.command("audit")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif"], case_sensitive=False),
    default="text",
    show_default=True,
)
@with_appcontext
def cli_audit(fmt: str) -> None:
    """Audit Flask-Deck security headers, session flags, RBAC, and searchable DB indexes."""
    decks = _get_registered_decks()
    if not decks:
        if fmt.lower() in {"json", "sarif"}:
            click.echo(json.dumps({"decks": [], "findings": []} if fmt.lower() == "json" else _findings_to_sarif([])))
        else:
            click.echo("No Flask-Deck instances registered on this Flask app.")
        return

    exit_code = 0
    flat_findings: list[dict[str, Any]] = []
    app_obj = current_app._get_current_object()  # type: ignore[attr-defined]
    for name, deck in decks.items():
        findings = run_security_audit(app_obj, deck)
        for item in findings:
            if item["severity"] in {"CRITICAL", "HIGH"}:
                exit_code = 1
            flat_findings.append({"deck": name, **item})

    fmt_clean = fmt.lower()
    if fmt_clean == "json":
        click.echo(json.dumps({"decks": list(decks.keys()), "findings": flat_findings}, indent=2))
    elif fmt_clean == "sarif":
        click.echo(json.dumps(_findings_to_sarif(flat_findings), indent=2))
    else:
        for name, deck in decks.items():
            click.echo(f"Auditing Flask-Deck '{name}' ({deck.config.environment})...")
            d_findings = [f for f in flat_findings if f["deck"] == name]
            if not d_findings:
                click.echo("  [OK] Zero security or index findings.")
                continue
            for item in d_findings:
                click.echo(f"  [{item['severity']}] ({item['category']}) {item['message']}")
    if exit_code:
        sys.exit(exit_code)


@deck_cli.command("scaffold")
@click.argument("slugs", nargs=-1)
@click.option("--output", type=click.Path(dir_okay=False, writable=True), default=None)
@with_appcontext
def cli_scaffold(slugs: tuple[str, ...], output: str | None) -> None:
    """Generate typed ModelView subclass boilerplate from registered SQLAlchemy models."""
    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.")
        return
    slug_filter = set(slugs)
    lines: list[str] = [
        "from __future__ import annotations",
        "",
        "from flask_deck import CurrencyFormatter, ModelView",
        "",
    ]
    for _name, deck in decks.items():
        for slug, view in deck.views.items():
            if slug_filter and slug not in slug_filter:
                continue
            m = view.meta
            cols = [f.name for f in m.fields if not f.is_sensitive and not f.is_heavy][:7]
            searches = [
                f.name
                for f in m.fields
                if f.field_type in {"string", "email"} and not f.is_sensitive
            ][:4]
            filters = [
                f.name
                for f in m.fields
                if (f.field_type in {"boolean", "enum", "date"} or f.fk_target_model is not None)
                and not f.is_sensitive
            ][:5]
            lines.extend(
                [
                    f"class {m.name}View(ModelView):",
                    f"    model = {m.name}",
                    f"    columns = {tuple(cols)!r}",
                    f"    searchable_columns = {tuple(searches)!r}",
                    f"    filterable_columns = {tuple(filters)!r}",
                    "",
                ]
            )
    text = "\n".join(lines)
    if output:
        from pathlib import Path

        Path(output).write_text(text + "\n", encoding="utf-8")
        click.echo(f"Wrote scaffold to {output}")
    else:
        click.echo(text)


def _run_demo(host: str = "127.0.0.1", port: int = 5055, open_browser: bool = False) -> None:
    import atexit
    import shutil
    import tempfile
    from pathlib import Path

    from flask_deck.demo import create_demo_app

    tmp_dir = Path(tempfile.mkdtemp(prefix="flask_deck_demo_"))
    db_file = tmp_dir / "demo.sqlite3"
    app = create_demo_app(db_uri=f"sqlite:///{db_file.as_posix()}", seed_profile="showcase")

    def _cleanup_demo() -> None:
        decks = app.extensions.get("flask_deck", {})
        for d in decks.values():
            if hasattr(d, "close"):
                d.close()
        shutil.rmtree(tmp_dir, ignore_errors=True)

    atexit.register(_cleanup_demo)
    url = f"http://{host}:{port}/admin/"
    click.echo(f"Flask-Deck Demo Workbench running at {url}")
    click.echo("Demo accounts (password: 'deck-demo-2026'):")
    click.echo("  - admin@acme.dev   (Superadmin — full access + revert)")
    click.echo("  - support@acme.dev (Support — masked PII, read-only billing, no delete)")
    click.echo("  - viewer@acme.dev  (Auditor — strict read-only inspection)")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    app.run(host=host, port=port, debug=False, use_reloader=False)


@deck_cli.group("jobs")
def cli_jobs() -> None:
    """Inspect and trigger @deck.scheduled_job operational jobs."""


@cli_jobs.command("list")
@with_appcontext
def cli_jobs_list() -> None:
    """List scheduled jobs registered on Flask-Deck instances."""
    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.")
        return
    for name, deck in decks.items():
        click.echo(f"Scheduled jobs for '{name}':")
        if not deck.scheduled_jobs:
            click.echo("  (none registered)")
            continue
        for spec in deck.scheduled_jobs.values():
            click.echo(f"  - {spec.name} [{spec.schedule}] {spec.label}")


@cli_jobs.command("run")
@click.argument("job_name")
@with_appcontext
def cli_jobs_run(job_name: str) -> None:
    """Execute a registered scheduled job by name synchronously and print status."""
    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.")
        return
    for _name, deck in decks.items():
        if job_name in deck.scheduled_jobs:
            rec = deck.run_scheduled_job_sync(job_name)
            click.echo(f"Scheduled job '{job_name}' -> {rec.status}: {rec.message}")
            if rec.status != "succeeded":
                sys.exit(1)
            return
    click.echo(f"Scheduled job '{job_name}' not found.", err=True)
    sys.exit(1)


@deck_cli.command("demo")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=5055, type=int, show_default=True)
@click.option("--open-browser", is_flag=True, default=False)
def cli_demo(host: str, port: int, open_browser: bool) -> None:
    """Launch the built-in Acme Cloud Ops SaaS demo workbench."""
    _run_demo(host=host, port=port, open_browser=open_browser)


@deck_cli.command("mcp")
@click.option("--deck-name", default=None, help="Target Deck blueprint name (defaults to first)")
@click.option("--api-key", envvar="FLASK_DECK_API_KEY", default=None, help="Scoped Bearer API key")
@with_appcontext
def cli_mcp(deck_name: str | None, api_key: str | None) -> None:
    """Run the JSON-RPC 2.0 Model Context Protocol (MCP) server over stdio."""
    from flask_deck.mcp_server import run_mcp_stdio

    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.", err=True)
        sys.exit(1)
    target = decks.get(deck_name) if deck_name else next(iter(decks.values()))
    if target is None:
        click.echo(f"Flask-Deck instance {deck_name!r} not found.", err=True)
        sys.exit(1)
    run_mcp_stdio(target, api_key_token=api_key)


def main(argv: Sequence[str] | None = None) -> int:
    """Standalone CLI entry point (`flask-deck demo`, `flask-deck version`)."""
    parser = argparse.ArgumentParser(
        prog="flask-deck",
        description="Flask-Deck — Precision Carbon Dark & Swiss Light Admin Panel for Flask.",
    )
    sub = parser.add_subparsers(dest="command")

    demo_p = sub.add_parser("demo", help="Launch the interactive SaaS demo workbench")
    demo_p.add_argument("--host", default="127.0.0.1")
    demo_p.add_argument("--port", type=int, default=5055)
    demo_p.add_argument("--open", dest="open_browser", action="store_true")

    sub.add_parser("version", help="Print installed flask-deck version")

    args = parser.parse_args(argv)
    if args.command == "demo":
        _run_demo(host=args.host, port=args.port, open_browser=args.open_browser)
        return 0
    if args.command == "version":
        from flask_deck import __version__

        print(f"flask-deck {__version__}")
        return 0

    parser.print_help()
    return 0
