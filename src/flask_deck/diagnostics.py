from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from flask import Flask

from flask_deck.audit import SQLAlchemyAuditStore
from flask_deck.auth import OpenAuthProvider
from flask_deck.checks import run_model_view_checks
from flask_deck.introspection import ModelMeta
from flask_deck.jobs import ThreadPoolJobBackend
from flask_deck.query import parse_search_column_spec
from flask_deck.storage import MemoryFileStorage

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def run_security_audit(app: Flask, deck: Deck) -> list[dict[str, str]]:
    """Inspect Flask + Deck configuration and SQLAlchemy indexes for security/performance findings."""
    findings: list[dict[str, str]] = []

    secret = app.secret_key
    if not secret:
        findings.append(
            {"severity": "CRITICAL", "category": "security", "message": "app.secret_key is not set."}
        )
    elif isinstance(secret, (str, bytes)) and len(secret) < 32:
        findings.append(
            {
                "severity": "WARN",
                "category": "security",
                "message": f"app.secret_key length is {len(secret)} bytes (recommended >= 32 bytes).",
            }
        )

    if not app.config.get("SESSION_COOKIE_HTTPONLY", True):
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "SESSION_COOKIE_HTTPONLY is False; session cookies are readable by JS.",
            }
        )
    if not app.config.get("SESSION_COOKIE_SAMESITE"):
        findings.append(
            {
                "severity": "WARN",
                "category": "security",
                "message": "SESSION_COOKIE_SAMESITE is unset (recommended 'Lax' or 'Strict').",
            }
        )
    if deck.config.environment == "production" and not app.config.get("SESSION_COOKIE_SECURE", False):
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "SESSION_COOKIE_SECURE is False in production environment.",
            }
        )
    if isinstance(deck.auth, OpenAuthProvider):
        findings.append(
            {
                "severity": "CRITICAL" if deck.config.environment == "production" else "WARN",
                "category": "auth",
                "message": "Deck is using OpenAuthProvider (unauthenticated access).",
            }
        )
    if deck.config.environment == "production" and not deck.config.require_mfa_for_superusers:
        findings.append(
            {
                "severity": "WARN",
                "category": "auth",
                "message": "require_mfa_for_superusers is False in production (enable TOTP 2FA enforcement).",
            }
        )
    if deck.config.environment == "production" and deck.config.demo_role_switcher:
        findings.append(
            {
                "severity": "HIGH",
                "category": "security",
                "message": "demo_role_switcher is enabled in config (locked out in production, set False).",
            }
        )
    if deck.config.environment == "production" and isinstance(
        deck.job_backend, ThreadPoolJobBackend
    ):
        findings.append(
            {
                "severity": "WARN",
                "category": "scale",
                "message": "ThreadPoolJobBackend is single-process; use SQLAlchemyJobBackend for multi-worker production.",
            }
        )
    if deck.config.environment == "production" and isinstance(
        deck.job_storage, MemoryFileStorage
    ):
        findings.append(
            {
                "severity": "WARN",
                "category": "scale",
                "message": "MemoryFileStorage is ephemeral and single-process; use LocalFileStorage or S3StorageBackend in production.",
            }
        )
    if (
        deck.config.environment == "production"
        and deck.mfa_store is not None
        and not deck.config.encryption_key
    ):
        findings.append(
            {
                "severity": "WARN",
                "category": "security",
                "message": "encryption_key is unset in production; configure DeckConfig(encryption_key=...) to encrypt MFA secrets at rest.",
            }
        )
    if isinstance(deck.audit_store, SQLAlchemyAuditStore) and deck.audit_store.hash_chain:
        chain_ok, chain_err = deck.audit_store.verify_chain()
        if not chain_ok:
            findings.append(
                {
                    "severity": "CRITICAL",
                    "category": "audit",
                    "message": chain_err or "Audit hash-chain integrity check failed.",
                }
            )

    # Schema performance checks
    for view in deck.views.values():
        meta: ModelMeta = view.meta
        for raw_spec in view.resolved_searchable:
            col_spec, _ = parse_search_column_spec(raw_spec)
            if "." in col_spec:
                continue
            if col_spec not in meta.indexed_fields:
                findings.append(
                    {
                        "severity": "INFO",
                        "category": "performance",
                        "message": (
                            f"{meta.name}.{col_spec} is in searchable_columns without a DB index "
                            "(consider adding index=True for large tables)."
                        ),
                    }
                )

    # Declarative ModelView system checks (DECK-E* / DECK-W*)
    for chk in run_model_view_checks(deck):
        sev = (
            "HIGH"
            if chk.severity == "error"
            else ("WARN" if chk.severity == "warn" else "INFO")
        )
        findings.append(
            {
                "severity": sev,
                "category": "model_check",
                "code": chk.code,
                "message": f"[{chk.code}] {chk.message}",
            }
        )

    return findings


def detect_flask_lens(app: Flask) -> dict[str, str] | None:
    """Detect an optional mounted ``flask-lens`` extension on ``app.extensions`` with zero dependency."""
    exts = getattr(app, "extensions", None)
    if not isinstance(exts, Mapping):
        return None
    for key in ("flask_lens", "lens"):
        ext = exts.get(key)
        if ext is not None:
            prefix = str(getattr(ext, "url_prefix", getattr(ext, "prefix", "/_lens")))
            ver = str(getattr(ext, "version", "detected"))
            return {"key": key, "url_prefix": prefix, "version": ver}
    return None
