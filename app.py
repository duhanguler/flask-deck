from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

_SRC_DIR = str(Path(__file__).resolve().parent / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from werkzeug.middleware.proxy_fix import ProxyFix  # noqa: E402

from flask_deck.demo import create_demo_app  # noqa: E402


def _resolve_db_uri() -> str:
    raw = os.environ.get("FLASK_DECK_DEMO_DB_URI") or os.environ.get("DATABASE_URL") or "sqlite:///:memory:"
    if raw.startswith("postgres://"):
        return "postgresql://" + raw[len("postgres://") :]
    return raw


def _resolve_secret_key() -> str:
    configured = os.environ.get("FLASK_DECK_SECRET_KEY")
    if configured:
        return configured
    seed = f"flask-deck-demo:{os.environ.get('VERCEL_DEPLOYMENT_ID', 'local')}:{os.environ.get('VERCEL_PROJECT_ID', 'demo')}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


app = create_demo_app(db_uri=_resolve_db_uri(), secret_key=_resolve_secret_key())
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)  # type: ignore[method-assign]
if os.environ.get("VERCEL"):
    app.config["SESSION_COOKIE_SECURE"] = True

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5055")), debug=False)
