from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import click
from flask import current_app
from flask.cli import AppGroup, with_appcontext

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


@deck_cli.command("audit")
@with_appcontext
def cli_audit() -> None:
    """Audit Flask-Deck security headers, session flags, RBAC, and searchable DB indexes."""
    decks = _get_registered_decks()
    if not decks:
        click.echo("No Flask-Deck instances registered on this Flask app.")
        return

    exit_code = 0
    for name, deck in decks.items():
        click.echo(f"Auditing Flask-Deck '{name}' ({deck.config.environment})...")
        findings = run_security_audit(current_app._get_current_object(), deck)  # type: ignore[attr-defined]
        if not findings:
            click.echo("  [OK] Zero security or index findings.")
            continue
        for item in findings:
            sev = item["severity"]
            if sev in {"CRITICAL", "HIGH"}:
                exit_code = 1
            click.echo(f"  [{sev}] ({item['category']}) {item['message']}")
    if exit_code:
        sys.exit(exit_code)


def _run_demo(host: str = "127.0.0.1", port: int = 5055, open_browser: bool = False) -> None:
    import atexit
    import shutil
    import tempfile
    from pathlib import Path

    from flask_deck.demo import create_demo_app

    tmp_dir = Path(tempfile.mkdtemp(prefix="flask_deck_demo_"))
    db_file = tmp_dir / "demo.sqlite3"
    app = create_demo_app(db_uri=f"sqlite:///{db_file.as_posix()}")

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


@deck_cli.command("demo")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=5055, type=int, show_default=True)
@click.option("--open-browser", is_flag=True, default=False)
def cli_demo(host: str, port: int, open_browser: bool) -> None:
    """Launch the built-in Acme Cloud Ops SaaS demo workbench."""
    _run_demo(host=host, port=port, open_browser=open_browser)


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
