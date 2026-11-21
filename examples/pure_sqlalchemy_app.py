from __future__ import annotations

import secrets

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import BasicAuthProvider, Deck


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False, index=True)
    prefix: Mapped[str] = mapped_column(sa.String(16), unique=True, nullable=False)
    secret_hash: Mapped[str] = mapped_column(
        sa.String(255),
        nullable=False,
        default=lambda: f"sha256:{secrets.token_hex(16)}",
    )
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secrets.token_hex(32)

    engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    auth = BasicAuthProvider.from_plain_passwords({"admin": "super-secret-password"})
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, title="Pure SA 2.0")
    deck.register(ApiKey)
    return app


if __name__ == "__main__":
    create_app().run(port=5056)
