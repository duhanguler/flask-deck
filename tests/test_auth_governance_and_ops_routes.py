"""Behavioral & security tests for auth, governance, audit revert, media ACLs, SQL console, and custom pages."""

from __future__ import annotations

import enum
import json
import time
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    ActivityWidget,
    Deck,
    DeckConfig,
    DeckUser,
    FileFieldConfig,
    InlineModelView,
    InMemoryAPIKeyStore,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemoryMFAStore,
    InMemoryPasskeyStore,
    InMemorySavedQueryStore,
    InMemorySessionStore,
    MemoryFileStorage,
    ModelView,
    OIDCAuthProvider,
    OIDCProviderConfig,
    OpenAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
)
from flask_deck.approvals import make_approval_request
from flask_deck.audit import make_audit_entry
from flask_deck.mfa import (
    MFA_PENDING_AT_KEY,
    MFA_PENDING_USER_KEY,
    MFAEnrollment,
    compute_totp,
    generate_totp_secret,
)
from flask_deck.security import (
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    CSRF_SESSION_KEY,
    LoginRateLimiter,
)
from flask_deck.storage import StoredFile
from tests._backends import sqlite_memory_engine


class OpsState(enum.Enum):
    DRAFT = "draft"
    LIVE = "live"


class OpsBase(DeclarativeBase):
    pass


class OpsDoc(OpsBase):
    __tablename__ = "ops_docs"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    state: Mapped[OpsState] = mapped_column(sa.Enum(OpsState), default=OpsState.DRAFT, nullable=False)
    secret_note: Mapped[str | None] = mapped_column(sa.String(100), nullable=True)
    file_key: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    presigned_key: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)
    restricted: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    attachments: Mapped[list[OpsAttachment]] = relationship(back_populates="doc")


class OpsAttachment(OpsBase):
    __tablename__ = "ops_attachments"
    id: Mapped[int] = mapped_column(primary_key=True)
    doc_id: Mapped[int] = mapped_column(sa.ForeignKey("ops_docs.id"), nullable=False)
    label: Mapped[str] = mapped_column(sa.String(60), nullable=False)
    blob_key: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    doc: Mapped[OpsDoc] = relationship(back_populates="attachments")


class PresignedMemoryStorage(MemoryFileStorage):
    """Memory storage subclass that advertises presigned redirect URLs."""

    def presigned_url(self, key: str, *, expires_in: int = 300) -> str | None:
        _ = expires_in
        if self.exists(key):
            return f"https://storage.example.test/signed/{key}"
        return None


def _extract_csrf(client: Any, url: str = "/admin/login") -> str:
    resp = client.get(url, follow_redirects=True)
    html = resp.get_data(as_text=True)
    marker = f'name="{CSRF_FORM_FIELD}" value="'
    idx = html.find(marker)
    if idx != -1:
        start = idx + len(marker)
        return html[start : html.find('"', start)]
    meta = 'name="csrf-token" content="'
    idx = html.find(meta)
    assert idx != -1, f"CSRF token missing on {url}"
    start = idx + len(meta)
    return html[start : html.find('"', start)]


def _login(client: Any, username: str, password: str) -> str:
    csrf = _extract_csrf(client, "/admin/login")
    resp = client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    return _extract_csrf(client, "/admin/")


def test_auth_mfa_reset_sessions_passkeys_impersonation_and_api_keys() -> None:
    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_super = auth.create_group(name="super", label="Super", permissions=frozenset({"*"}))
        g_ops = auth.create_group(
            name="ops",
            label="Ops",
            permissions=frozenset({"docs:view", "api_keys:manage"}),
        )
        u_root = auth.create_user(
            username="root",
            password="RootPassword1!",
            email="root@example.com",
            is_superuser=True,
            group_ids=[g_super.id],
        )
        u_ops = auth.create_user(
            username="opsuser",
            password="OpsPassword1!",
            email="ops@example.com",
            is_superuser=False,
            group_ids=[g_ops.id],
        )
        auth._demo_account_ids = (u_root.id, u_ops.id)

        sent_resets: list[tuple[str, str, str]] = []

        def _notifier(user: DeckUser, url: str, token: str) -> None:
            sent_resets.append((user.username, url, token))

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "auth-routes-secret-32-bytes-long!"
        app.config["TESTING"] = True

        mfa_store = InMemoryMFAStore()
        sess_store = InMemorySessionStore()
        api_keys = InMemoryAPIKeyStore()

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=InMemoryAuditStore(),
            mfa_store=mfa_store,
            session_store=sess_store,
            passkey_store=InMemoryPasskeyStore(),
            api_key_store=api_keys,
            rate_limit_store=LoginRateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=60),
            password_reset_notifier=_notifier,
            require_mfa_for_superusers=True,
            enable_impersonation=True,
            impersonate_read_only=True,
            demo_role_switcher=True,
        )

        try:
            # 1. Login brute-force rate limit -> 429 + Retry-After
            c_rl = app.test_client()
            csrf_rl = _extract_csrf(c_rl, "/admin/login")
            for _ in range(3):
                r = c_rl.post(
                    "/admin/login",
                    data={"username": "victim", "password": "wrong", CSRF_FORM_FIELD: csrf_rl},
                )
                assert r.status_code in {200, 401}
            r_locked = c_rl.post(
                "/admin/login",
                data={"username": "victim", "password": "wrong", CSRF_FORM_FIELD: csrf_rl},
            )
            assert r_locked.status_code == 429
            assert "Retry-After" in r_locked.headers

            # 2. Forgot password + reset password lifecycle (invalid token, mismatch, weak, valid)
            c_fp = app.test_client()
            csrf_fp = _extract_csrf(c_fp, "/admin/login/forgot-password")
            assert c_fp.post(
                "/admin/login/forgot-password",
                data={"identifier": "ops@example.com", CSRF_FORM_FIELD: csrf_fp},
            ).status_code == 200
            assert len(sent_resets) == 1
            _, _, reset_tok = sent_resets[0]

            assert c_fp.get("/admin/login/reset-password/nonexistent").status_code == 200
            r_rg = c_fp.get(f"/admin/login/reset-password/{reset_tok}")
            assert r_rg.status_code == 200
            csrf_rp = _extract_csrf(c_fp, f"/admin/login/reset-password/{reset_tok}")
            # Mismatch passwords
            assert c_fp.post(
                f"/admin/login/reset-password/{reset_tok}",
                data={
                    "new_password": "NewOpsPassword2!",
                    "confirm_password": "DifferentPassword!",
                    CSRF_FORM_FIELD: csrf_rp,
                },
            ).status_code == 200
            # Weak password
            assert c_fp.post(
                f"/admin/login/reset-password/{reset_tok}",
                data={
                    "new_password": "123",
                    "confirm_password": "123",
                    CSRF_FORM_FIELD: csrf_rp,
                },
            ).status_code == 200
            # Valid password reset succeeds and redirects to login
            r_reset_ok = c_fp.post(
                f"/admin/login/reset-password/{reset_tok}",
                data={
                    "new_password": "NewOpsPassword2!",
                    "confirm_password": "NewOpsPassword2!",
                    CSRF_FORM_FIELD: csrf_rp,
                },
            )
            assert r_reset_ok.status_code == 302 and "/login" in r_reset_ok.headers["Location"]

            # 3. Superuser login -> MFA setup, wrong code, valid enable, superuser disable blocked
            c = app.test_client()
            csrf = _login(c, "root", "RootPassword1!")
            assert c.get("/admin/_security/mfa").status_code == 200
            with c.session_transaction() as sess:
                pending_secret = sess.get("_deck_mfa_setup_secret")
            assert pending_secret
            # Invalid TOTP on enable
            r_bad_mfa = c.post(
                "/admin/_security/mfa",
                data={"action": "enable", "code": "000000", CSRF_FORM_FIELD: csrf},
            )
            assert r_bad_mfa.status_code == 200
            # Valid TOTP enables MFA
            valid_code = compute_totp(pending_secret)
            r_ok_mfa = c.post(
                "/admin/_security/mfa",
                data={"action": "enable", "code": valid_code, CSRF_FORM_FIELD: csrf},
            )
            assert r_ok_mfa.status_code == 200
            assert mfa_store.get(u_root.id) is not None
            # Superuser cannot disable MFA when enforce_mfa_for_superusers=True
            r_dis_block = c.post(
                "/admin/_security/mfa",
                data={"action": "disable", "code": valid_code, CSRF_FORM_FIELD: csrf},
            )
            assert r_dis_block.status_code == 200
            assert mfa_store.get(u_root.id) is not None

            # 4. Login with MFA pending TTL expiry & valid TOTP verification
            c_mfa = app.test_client()
            csrf_m = _extract_csrf(c_mfa, "/admin/login")
            r_l1 = c_mfa.post(
                "/admin/login",
                data={"username": "root", "password": "RootPassword1!", CSRF_FORM_FIELD: csrf_m},
            )
            assert r_l1.status_code == 302 and "/login/mfa" in r_l1.headers["Location"]
            # Expired pending timestamp bounces back to /login
            with c_mfa.session_transaction() as sess:
                sess[MFA_PENDING_AT_KEY] = int(time.time()) - 9999
            r_exp = c_mfa.get("/admin/login/mfa")
            assert r_exp.status_code == 302 and "/login" in r_exp.headers["Location"]
            # Fresh pending challenge + 3 wrong codes -> 429 MFA lockout
            with c_mfa.session_transaction() as sess:
                sess[MFA_PENDING_USER_KEY] = u_root.id
                sess[MFA_PENDING_AT_KEY] = int(time.time())
            csrf_m2 = _extract_csrf(c_mfa, "/admin/login/mfa")
            for _ in range(3):
                assert c_mfa.post(
                    "/admin/login/mfa",
                    data={"code": "999999", CSRF_FORM_FIELD: csrf_m2},
                ).status_code == 200
            r_mfa_429 = c_mfa.post(
                "/admin/login/mfa",
                data={"code": "999999", CSRF_FORM_FIELD: csrf_m2},
            )
            assert r_mfa_429.status_code == 429 and "Retry-After" in r_mfa_429.headers

            # 5. Sessions listing (mine & all), demo_safe_mode IP masking, revoke-others & revoke
            assert c.get("/admin/_security/sessions?scope=all").status_code == 200
            r_ro = c.post("/admin/_security/sessions/revoke-others", data={CSRF_FORM_FIELD: csrf})
            assert r_ro.status_code == 302
            assert c.post(
                "/admin/_security/sessions/nonexistent/revoke",
                data={CSRF_FORM_FIELD: csrf},
            ).status_code == 302

            # 6. Passkey endpoints guards
            assert c.get("/admin/_security/passkeys").status_code == 200
            assert c.post("/admin/_security/passkeys/register/verify", json={}, headers={CSRF_HEADER_NAME: csrf}).status_code in {400, 501}
            assert c.post("/admin/_security/passkeys/missing-cred/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert c.post("/admin/login/passkey/verify", json={}, headers={CSRF_HEADER_NAME: csrf}).status_code in {400, 501}

            # 7. API keys UI (superuser & non-superuser role clamping, invalid/overflow TTL rejected, revoke)
            c_ops = app.test_client()
            csrf_o = _login(c_ops, "opsuser", "NewOpsPassword2!")
            assert c_ops.get("/admin/_security/api-keys").status_code == 200
            for bad_ttl in ("notanint", "-5", "9999999999"):
                r_bad_ttl = c_ops.post(
                    "/admin/_security/api-keys/create",
                    data={
                        "name": "Bad TTL Key",
                        "scopes": "docs:view",
                        "roles": "ops",
                        "ttl_days": bad_ttl,
                        CSRF_FORM_FIELD: csrf_o,
                    },
                )
                assert r_bad_ttl.status_code == 302
            assert len(api_keys.list_keys(owner_id=u_ops.id)) == 0
            r_kcreate = c_ops.post(
                "/admin/_security/api-keys/create",
                data={
                    "name": "Ops Key",
                    "scopes": "docs:view",
                    "roles": "super,ops",  # super must be clamped away!
                    "is_superuser": "1",   # must be ignored for non-superuser!
                    "ttl_days": "30",
                    CSRF_FORM_FIELD: csrf_o,
                },
            )
            assert r_kcreate.status_code == 302
            created_keys = api_keys.list_keys(owner_id=u_ops.id)
            assert len(created_keys) == 1
            assert created_keys[0].is_superuser is False
            assert "super" not in created_keys[0].roles
            assert c_ops.post(
                "/admin/_security/api-keys/nonexistent/revoke",
                data={CSRF_FORM_FIELD: csrf_o},
            ).status_code == 302
            assert c_ops.post(
                f"/admin/_security/api-keys/{created_keys[0].id}/revoke",
                data={CSRF_FORM_FIELD: csrf_o},
            ).status_code == 302

            # 8. Impersonation guards & read-only blocks
            # Non-superuser blocked
            assert c_ops.post(
                "/admin/_impersonate/start",
                data={"target_user_id": u_root.id, CSRF_FORM_FIELD: csrf_o},
            ).status_code == 403
            # Self/superuser impersonation rejected gracefully
            r_imp_self = c.post(
                "/admin/_impersonate/start",
                data={"target_user_id": u_root.id, CSRF_FORM_FIELD: csrf},
            )
            assert r_imp_self.status_code == 302
            # Valid impersonation of opsuser -> read-only blocks sensitive security endpoints
            r_imp_ok = c.post(
                "/admin/_impersonate/start",
                data={"target_user_id": u_ops.id, CSRF_FORM_FIELD: csrf},
            )
            assert r_imp_ok.status_code == 302
            csrf_imp = _extract_csrf(c, "/admin/")
            assert c.post(
                "/admin/_security/api-keys/create",
                data={"name": "Blocked", CSRF_FORM_FIELD: csrf_imp},
            ).status_code == 403
            assert c.post(
                f"/admin/_security/api-keys/{created_keys[0].id}/revoke",
                data={CSRF_FORM_FIELD: csrf_imp},
            ).status_code == 403
            assert c.post("/admin/_impersonate/stop", data={CSRF_FORM_FIELD: csrf_imp}).status_code == 302

            # 9. Demo role switcher (invalid 404, valid 302)
            csrf_after = _extract_csrf(c, "/admin/")
            assert c.post(
                "/admin/_demo/switch-role",
                data={"account_id": "unknown", CSRF_FORM_FIELD: csrf_after},
            ).status_code == 404
            r_sw = c.post(
                "/admin/_demo/switch-role",
                data={"account_id": u_ops.id, "next": "/admin/", CSRF_FORM_FIELD: csrf_after},
            )
            assert r_sw.status_code == 302

            # 10. Logout clears session
            csrf_out = _extract_csrf(c, "/admin/")
            r_out = c.post("/admin/logout", data={CSRF_FORM_FIELD: csrf_out})
            assert r_out.status_code == 302
        finally:
            deck.close()


def test_governance_ops_media_sql_console_and_custom_pages() -> None:
    file_store = MemoryFileStorage()
    presigned_store = PresignedMemoryStorage()
    inline_store = MemoryFileStorage()

    class AttachInline(InlineModelView):
        model = OpsAttachment
        fk_column = "doc_id"
        columns = ("label", "blob_key")
        file_fields = MappingProxyType({"blob_key": FileFieldConfig(storage=inline_store, kind="file")})

    class OpsDocView(ModelView):
        model = OpsDoc
        slug = "docs"
        category = "Documents"
        soft_delete_column = "deleted_at"
        version_column = "version"
        inlines = (AttachInline,)
        file_fields = MappingProxyType(
            {
                "file_key": FileFieldConfig(storage=file_store, kind="file"),
                "presigned_key": FileFieldConfig(
                    storage=presigned_store, kind="file", use_presigned_redirect=True
                ),
            }
        )

        def can_view_record(self, obj: Any, user: Any) -> bool:
            return not (obj.restricted and user is not None and not user.is_superuser)

        def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
            _ = obj
            if data.get("title") == "INVALID_REVERT":
                return {"title": ["Invalid title on revert"]}
            return {}

    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        sf_main: StoredFile = file_store.save(b"hello-media", key="docs/main.txt", content_type="text/plain")
        sf_pre: StoredFile = presigned_store.save(b"signed-body", key="docs/signed.txt", content_type="text/plain")
        sf_inl: StoredFile = inline_store.save(b"inline-media", key="docs/inl.txt", content_type="text/plain")

        with SessionLocal() as s:
            d1 = OpsDoc(title="Alpha Doc", file_key=sf_main.key, presigned_key=sf_pre.key)
            d_rest = OpsDoc(title="Restricted", restricted=True, file_key=sf_main.key)
            d_trash = OpsDoc(
                title="Trashed",
                file_key=sf_main.key,
                deleted_at=datetime.now(timezone.utc),
            )
            d_miss = OpsDoc(title="Missing Blob", file_key="does-not-exist.txt")
            s.add_all([d1, d_rest, d_trash, d_miss])
            s.flush()
            a1 = OpsAttachment(doc_id=d1.id, label="Att 1", blob_key=sf_inl.key)
            a_trash = OpsAttachment(doc_id=d_trash.id, label="Att Trash", blob_key=sf_inl.key)
            s.add_all([a1, a_trash])
            s.commit()
            d1_id, d_rest_id, d_trash_id, d_miss_id = d1.id, d_rest.id, d_trash.id, d_miss.id
            a1_id, a_trash_id = a1.id, a_trash.id

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_super = auth.create_group(name="super", label="Super", permissions=frozenset({"*"}))
        g_rev = auth.create_group(
            name="reviewer",
            label="Reviewer",
            permissions=frozenset(
                {
                    "docs:view",
                    "docs:edit",
                    "approvals:view",
                    "approvals:review",
                    "sql:execute",
                    "audit:view",
                    "audit:revert",
                }
            ),
            hidden_fields={"docs": frozenset({"secret_note"})},
            masked_fields={"docs": frozenset({"file_key"})},
        )
        u_adm = auth.create_user(
            username="admin", password="AdminPassword1!", is_superuser=True, group_ids=[g_super.id]
        )
        auth.create_user(
            username="reviewer", password="ReviewerPassword1!", is_superuser=False, group_ids=[g_rev.id]
        )

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "gov-ops-secret-32-bytes-long!!!!"
        app.config["TESTING"] = True

        audit_store = InMemoryAuditStore()
        approval_store = InMemoryApprovalStore()
        saved_queries = InMemorySavedQueryStore()

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=audit_store,
            approval_store=approval_store,
            saved_query_store=saved_queries,
            session_store=InMemorySessionStore(),
            environment="production",
            require_confirm_text_in_prod=True,
            enable_sql_console=True,
            enable_audit_revert=True,
            enable_user_preferences=True,
        )
        deck.register(OpsDocView)

        @deck.page("ops-feed", title="Ops Feed", category="Documents", permission="docs:view")
        def ops_feed(ctx: Any) -> list[Any]:
            _ = ctx
            return [ActivityWidget(title="Recent Activity", entries=())]

        @deck.page("super-only", title="Super Only", permission="super:only")
        def super_only(ctx: Any) -> list[Any]:
            _ = ctx
            return []

        try:
            c = app.test_client()
            csrf = _login(c, "admin", "AdminPassword1!")
            rc = app.test_client()
            csrf_r = _login(rc, "reviewer", "ReviewerPassword1!")

            # 1. Preferences validation
            assert c.post("/admin/_preferences", data={"locale": "xx", CSRF_FORM_FIELD: csrf}).status_code == 400
            assert c.post("/admin/_preferences", data={"timezone": "Mars/Olympus", CSRF_FORM_FIELD: csrf}).status_code == 400
            assert c.post(
                "/admin/_preferences",
                data={"locale": "tr", "timezone": "Europe/Istanbul", "next": "/admin/", CSRF_FORM_FIELD: csrf},
            ).status_code == 302

            # 2. Edit doc once to generate an audit entry, then test /_audit + /_audit/export + /_audit/<id>/revert
            r_ed = c.post(
                f"/admin/docs/{d1_id}/edit",
                data={CSRF_FORM_FIELD: csrf, "title": "Beta Doc", "state": "live"},
            )
            assert r_ed.status_code == 302
            assert c.get("/admin/_audit?date_from=bad&date_to=bad&page=bad").status_code == 200
            assert c.get("/admin/_audit/export?format=xml").status_code == 400
            r_acsv = c.get("/admin/_audit/export?format=csv")
            assert r_acsv.status_code == 200 and "Beta Doc" in r_acsv.get_data(as_text=True)
            r_ajsonl = c.get("/admin/_audit/export?format=jsonl")
            assert r_ajsonl.status_code == 200 and "Beta Doc" in r_ajsonl.get_data(as_text=True)

            entries, _ = audit_store.list_entries(model_slug="docs", limit=10)
            upd_entry = next(e for e in entries if e.action == "update")
            # Missing entry -> 404
            assert c.post("/admin/_audit/missing-id/revert", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            # Production guard rejects missing REVERT confirm_text
            r_rev_no = c.post(
                f"/admin/_audit/{upd_entry.id}/revert",
                data={"confirm_text": "NOPE", CSRF_FORM_FIELD: csrf},
            )
            assert r_rev_no.status_code == 302
            # Valid REVERT restores Alpha Doc and bumps version
            r_rev_ok = c.post(
                f"/admin/_audit/{upd_entry.id}/revert",
                data={"confirm_text": "REVERT", CSRF_FORM_FIELD: csrf},
            )
            assert r_rev_ok.status_code == 302
            with SessionLocal() as s:
                refreshed = s.get(OpsDoc, d1_id)
                assert refreshed is not None and refreshed.title == "Alpha Doc" and refreshed.version >= 3

            # 3. Approvals list (invalid status fallback) + four-eyes self-block + reviewer approve & reject
            req_edit = approval_store.create(
                make_approval_request(
                    model_slug="docs",
                    model_label="Doc",
                    operation="edit",
                    record_pk=str(d1_id),
                    record_repr="Alpha Doc",
                    payload={"form_items": [["title", "Approved Title"], ["state", "draft"]]},
                    diff={"title": {"old": "Alpha Doc", "new": "Approved Title"}},
                    reason="Routine update",
                    requester_id=u_adm.id,
                    requester_name="admin",
                )
            )
            req_rej = approval_store.create(
                make_approval_request(
                    model_slug="docs",
                    model_label="Doc",
                    operation="delete",
                    record_pk=str(d1_id),
                    record_repr="Alpha Doc",
                    payload={"force": False},
                    diff={},
                    reason="Cancel me",
                    requester_id=u_adm.id,
                    requester_name="admin",
                )
            )
            assert c.get("/admin/_approvals?status=bogus").status_code == 200
            # Self-approval blocked (four-eyes fail-closed 403)
            assert c.post(
                f"/admin/_approvals/{req_edit.id}/approve",
                data={CSRF_FORM_FIELD: csrf},
            ).status_code == 403
            assert approval_store.get(req_edit.id).status == "pending"  # type: ignore[union-attr]
            # Reviewer approves -> executes edit!
            assert rc.post(
                f"/admin/_approvals/{req_edit.id}/approve",
                data={"review_note": "LGTM", CSRF_FORM_FIELD: csrf_r},
            ).status_code == 302
            assert approval_store.get(req_edit.id).status == "approved"  # type: ignore[union-attr]
            # Re-approving already-resolved request handled gracefully
            assert rc.post(
                f"/admin/_approvals/{req_edit.id}/approve",
                data={CSRF_FORM_FIELD: csrf_r},
            ).status_code == 302
            # Reviewer rejects second request & re-rejecting handled gracefully
            assert rc.post(
                f"/admin/_approvals/{req_rej.id}/reject",
                data={"review_note": "Denied", CSRF_FORM_FIELD: csrf_r},
            ).status_code == 302
            assert rc.post(
                f"/admin/_approvals/{req_rej.id}/reject",
                data={CSRF_FORM_FIELD: csrf_r},
            ).status_code == 302
            assert rc.post(
                "/admin/_approvals/nonexistent/approve",
                data={CSRF_FORM_FIELD: csrf_r},
            ).status_code == 404
            assert rc.post(
                "/admin/_approvals/nonexistent/reject",
                data={CSRF_FORM_FIELD: csrf_r},
            ).status_code == 404

            # 4. Media & Inline Media ACLs
            assert c.get(f"/admin/_media/docs/file_key/{d1_id}").status_code == 200
            assert c.get(f"/admin/_media/docs/unknown_field/{d1_id}").status_code == 404
            assert c.get(f"/admin/_media/docs/file_key/{d_trash_id}").status_code == 404
            assert c.get(f"/admin/_media/docs/file_key/{d_miss_id}").status_code == 404
            r_pre = c.get(f"/admin/_media/docs/presigned_key/{d1_id}")
            assert r_pre.status_code == 302 and "storage.example.test" in r_pre.headers["Location"]
            # Reviewer has file_key masked -> 403; restricted doc -> 403
            assert rc.get(f"/admin/_media/docs/file_key/{d1_id}").status_code == 403
            assert rc.get(f"/admin/_media/docs/presigned_key/{d_rest_id}").status_code == 403
            # Inline media
            assert c.get(f"/admin/_media/docs/_inline/ops-attachments/blob_key/{a1_id}").status_code == 200
            assert c.get(f"/admin/_media/docs/_inline/unknown/blob_key/{a1_id}").status_code == 404
            assert c.get(f"/admin/_media/docs/_inline/ops-attachments/bad_field/{a1_id}").status_code == 404
            assert c.get(f"/admin/_media/docs/_inline/ops-attachments/blob_key/{a_trash_id}").status_code == 404

            # 5. Category index, Schema, Diagnostics, Custom Pages
            assert c.get("/admin/_category/documents").status_code == 200
            assert c.get("/admin/_category/nonexistent").status_code == 404
            assert c.get("/admin/_schema").status_code == 200
            assert rc.get("/admin/_schema").status_code == 403
            assert c.get("/admin/_diagnostics").status_code == 200
            assert rc.get("/admin/_diagnostics").status_code == 403
            assert c.get("/admin/_page/ops-feed").status_code == 200
            assert c.get("/admin/_page/unknown-page").status_code == 404
            assert rc.get("/admin/_page/super-only").status_code == 403

            # 6. SQL Console: table, explain, CSV, save, pin, delete ownership guards
            assert c.get("/admin/_sql").status_code == 200
            assert c.post(
                "/admin/_sql",
                data={"sql": "SELECT id, title FROM ops_docs", "output": "table", CSRF_FORM_FIELD: csrf},
            ).status_code == 200
            assert c.post(
                "/admin/_sql",
                data={"sql": "SELECT id, title FROM ops_docs", "output": "explain", CSRF_FORM_FIELD: csrf},
            ).status_code == 200
            r_scsv = c.post(
                "/admin/_sql",
                data={"sql": "SELECT id, title FROM ops_docs", "output": "csv", CSRF_FORM_FIELD: csrf},
            )
            assert r_scsv.status_code == 200 and "Approved Title" in r_scsv.get_data(as_text=True)

            # Save blocked mutation SQL rejected; valid SELECT saved
            assert c.post(
                "/admin/_sql/save",
                data={"name": "Bad", "sql": "DELETE FROM ops_docs", CSRF_FORM_FIELD: csrf},
            ).status_code == 302
            assert c.post(
                "/admin/_sql/save",
                data={"name": "", "sql": "", CSRF_FORM_FIELD: csrf},
            ).status_code == 302
            assert c.post(
                "/admin/_sql/save",
                data={
                    "name": "Doc Count",
                    "sql": "SELECT COUNT(*) AS cnt FROM ops_docs",
                    "chart_type": "bogus",
                    "pin": "1",
                    CSRF_FORM_FIELD: csrf,
                },
            ).status_code == 302
            sq_list = saved_queries.list_queries()
            assert len(sq_list) == 1
            sq_id = sq_list[0].id
            assert c.get(f"/admin/_sql?saved={sq_id}").status_code == 200
            # Reviewer (non-owner, non-superuser) cannot pin or delete admin's saved query -> 403
            assert rc.post(f"/admin/_sql/{sq_id}/pin", data={CSRF_FORM_FIELD: csrf_r}).status_code == 403
            assert rc.post(f"/admin/_sql/{sq_id}/delete", data={CSRF_FORM_FIELD: csrf_r}).status_code == 403
            # Owner can toggle pin & delete
            assert c.post(
                f"/admin/_sql/{sq_id}/pin",
                data={"chart_type": "line", CSRF_FORM_FIELD: csrf},
            ).status_code == 302
            assert c.post("/admin/_sql/missing/pin", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert c.post(f"/admin/_sql/{sq_id}/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert c.post("/admin/_sql/missing/delete", data={CSRF_FORM_FIELD: csrf}).status_code == 302
        finally:
            deck.close()


def test_sso_mfa_challenge_non_super_mfa_disable_and_revert_guards() -> None:
    # 1. Non-superuser MFA enable & disable + forgot-password 429 rate-limit + non-OIDC SSO 404
    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_ops = auth.create_group(name="ops", label="Ops", permissions=frozenset({"docs:view"}))
        u_ops = auth.create_user(
            username="opsuser",
            password="OpsPassword1!",
            email="ops@example.com",
            is_superuser=False,
            group_ids=[g_ops.id],
        )

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "mfa-disable-secret-32-bytes-long!"
        app.config["TESTING"] = True
        mfa_store = InMemoryMFAStore()
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            audit_store=False,
            approval_store=False,
            mfa_store=mfa_store,
            session_store=InMemorySessionStore(),
            rate_limit_store=LoginRateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=60),
            password_reset_notifier=lambda _u, _url, _tok: None,
            enable_user_preferences=False,
            enable_sql_console=False,
        )
        try:
            c = app.test_client()
            csrf = _login(c, "opsuser", "OpsPassword1!")

            # Disabled features return 404
            assert c.post("/admin/_preferences", data={CSRF_FORM_FIELD: csrf}).status_code == 404
            assert c.get("/admin/_audit").status_code == 404
            assert c.get("/admin/_approvals").status_code == 404
            assert c.get("/admin/_sql").status_code == 404
            assert c.get("/admin/login/sso/okta").status_code == 404
            assert c.get("/admin/login/sso/okta/callback").status_code == 404

            # Non-superuser enables MFA, fails disable with wrong code, then disables with valid code
            assert c.get("/admin/_security/mfa").status_code == 200
            with c.session_transaction() as sess:
                setup_sec = sess.get("_deck_mfa_setup_secret")
            assert setup_sec
            c_en = compute_totp(setup_sec)
            assert c.post(
                "/admin/_security/mfa",
                data={"action": "enable", "code": c_en, CSRF_FORM_FIELD: csrf},
            ).status_code == 200
            assert mfa_store.get(u_ops.id) is not None
            # Wrong code keeps MFA enabled
            assert c.post(
                "/admin/_security/mfa",
                data={"action": "disable", "code": "000000", CSRF_FORM_FIELD: csrf},
            ).status_code == 200
            assert mfa_store.get(u_ops.id) is not None
            # Next time-step valid code disables MFA cleanly
            rec_e = mfa_store.get(u_ops.id)
            assert rec_e is not None
            next_code = compute_totp(rec_e.secret, timestamp=time.time() + 30)
            assert c.post(
                "/admin/_security/mfa",
                data={"action": "disable", "code": next_code, CSRF_FORM_FIELD: csrf},
            ).status_code == 200
            assert mfa_store.get(u_ops.id) is None

            # Forgot-password 429 rate-limit lockout
            c_fp = app.test_client()
            csrf_fp = _extract_csrf(c_fp, "/admin/login/forgot-password")
            for _ in range(2):
                assert c_fp.post(
                    "/admin/login/forgot-password",
                    data={"identifier": "nobody@example.com", CSRF_FORM_FIELD: csrf_fp},
                ).status_code == 200
            r_fp_429 = c_fp.post(
                "/admin/login/forgot-password",
                data={"identifier": "nobody@example.com", CSRF_FORM_FIELD: csrf_fp},
            )
            assert r_fp_429.status_code == 429 and "Retry-After" in r_fp_429.headers
        finally:
            deck.close()

    # 2. SSO-only OIDCAuthProvider + SSO callback with MFA challenge + /_rbac 404 + audit revert guards
    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        sso_user = DeckUser(id="sso-1", username="sso_ada", display_name="Ada SSO", roles=("admin",), is_superuser=True)
        sso_auth = OIDCAuthProvider(
            providers=[
                OIDCProviderConfig.okta(
                    domain="https://okta.example.test",
                    client_id="cid",
                    client_secret="csec",
                )
            ],
            roles=[Role("admin", permissions=frozenset({"*"}))],
            http_transport=lambda url, method, data, headers, timeout: (
                200,
                json.dumps(
                    {
                        "authorization_endpoint": "https://okta.example.test/authorize",
                        "token_endpoint": "https://okta.example.test/token",
                        "jwks_uri": "https://okta.example.test/jwks",
                    }
                ).encode("utf-8"),
            ),
        )
        sso_auth.complete_callback = lambda prov, *, code, state, redirect_uri: (sso_user, "/admin/")  # type: ignore[method-assign]

        mfa_sec = generate_totp_secret()
        mfa_store2 = InMemoryMFAStore()
        mfa_store2.save(MFAEnrollment(user_id=sso_user.id, secret=mfa_sec, enabled=True))

        app_sso = Flask(__name__)
        app_sso.config["SECRET_KEY"] = "sso-mfa-secret-32-bytes-long!!!!"
        app_sso.config["TESTING"] = True
        deck_sso = Deck(
            app_sso,
            session_factory=SessionLocal,
            engine=eng,
            auth=sso_auth,
            mfa_store=mfa_store2,
            session_store=InMemorySessionStore(),
            audit_store=False,
        )
        try:
            cs = app_sso.test_client()
            assert cs.get("/admin/login").status_code == 200
            with cs.session_transaction() as sess:
                csrf_s = "s" * 40
                sess[CSRF_SESSION_KEY] = csrf_s
            # SSO-only provider refuses password POST
            r_pwd_no = cs.post(
                "/admin/login",
                data={"username": "x", "password": "y", CSRF_FORM_FIELD: csrf_s},
            )
            assert r_pwd_no.status_code in {403, 404}
            # Unknown SSO provider -> 404
            assert cs.get("/admin/login/sso/unknown").status_code == 404
            assert cs.get("/admin/login/sso/unknown/callback").status_code == 404
            # Known SSO provider redirects to authorize URL
            r_authz = cs.get("/admin/login/sso/okta?next=/admin/")
            assert r_authz.status_code == 302 and "okta.example.test" in r_authz.headers["Location"]
            # Callback with MFA enrolled sets pending SSO state & redirects to /login/mfa
            r_cb = cs.get("/admin/login/sso/okta/callback?code=abc&state=xyz")
            assert r_cb.status_code == 302 and "/login/mfa" in r_cb.headers["Location"]
            # Complete SSO+MFA challenge with valid TOTP
            csrf_m = _extract_csrf(cs, "/admin/login/mfa")
            r_m_ok = cs.post(
                "/admin/login/mfa",
                data={"code": compute_totp(mfa_sec), CSRF_FORM_FIELD: csrf_m},
            )
            assert r_m_ok.status_code == 302 and r_m_ok.headers["Location"].endswith("/admin/")
        finally:
            deck_sso.close()

    # 3. Audit revert guards (soft-deleted, approval-required, validation failure, missing record) + /_rbac 404
    class GovDocView(ModelView):
        model = OpsDoc
        slug = "gov-docs"
        soft_delete_column = "deleted_at"
        approval_required = ("edit",)

    class ValDocView(ModelView):
        model = OpsDoc
        slug = "val-docs"
        soft_delete_column = "deleted_at"

        def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
            _ = obj
            if data.get("title") == "INVALID_REVERT":
                return {"title": ["Rejected revert"]}
            return {}

    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SessionLocal() as s:
            d_ok = OpsDoc(title="Live")
            d_tr = OpsDoc(title="Trashed", deleted_at=datetime.now(timezone.utc))
            s.add_all([d_ok, d_tr])
            s.commit()
            d_ok_id, d_tr_id = d_ok.id, d_tr.id

        audit_s = InMemoryAuditStore()
        e_trash = audit_s.record(
            make_audit_entry(
                actor_id="1",
                actor_name="adm",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="val-docs",
                model_label="Doc",
                record_pk=str(d_tr_id),
                record_repr="Trashed",
                changes={"title": {"old": "Before", "new": "Trashed"}},
            )
        )
        e_val = audit_s.record(
            make_audit_entry(
                actor_id="1",
                actor_name="adm",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="val-docs",
                model_label="Doc",
                record_pk=str(d_ok_id),
                record_repr="Live",
                changes={"title": {"old": "INVALID_REVERT", "new": "Live"}},
            )
        )
        e_gov = audit_s.record(
            make_audit_entry(
                actor_id="1",
                actor_name="adm",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="gov-docs",
                model_label="Doc",
                record_pk=str(d_ok_id),
                record_repr="Live",
                changes={"title": {"old": "Old", "new": "Live"}},
            )
        )
        e_miss = audit_s.record(
            make_audit_entry(
                actor_id="1",
                actor_name="adm",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="val-docs",
                model_label="Doc",
                record_pk="99999",
                record_repr="Gone",
                changes={"title": {"old": "Old", "new": "Gone"}},
            )
        )

        app_rev = Flask(__name__)
        app_rev.config["SECRET_KEY"] = "revert-guards-secret-32-bytes!!!"
        app_rev.config["TESTING"] = True
        deck_rev = Deck(
            app_rev,
            session_factory=SessionLocal,
            engine=eng,
            auth=OpenAuthProvider(),
            audit_store=audit_s,
            approval_store=InMemoryApprovalStore(),
            enable_audit_revert=True,
        )
        deck_rev.register(GovDocView, ValDocView)
        try:
            cr = app_rev.test_client()
            csrf_r = _extract_csrf(cr, "/admin/")
            assert cr.get("/admin/_rbac").status_code == 404  # OpenAuthProvider has 0 roles
            assert cr.post(f"/admin/_audit/{e_trash.id}/revert", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert cr.post(f"/admin/_audit/{e_val.id}/revert", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert cr.post(f"/admin/_audit/{e_gov.id}/revert", data={CSRF_FORM_FIELD: csrf_r}).status_code == 302
            assert cr.post(f"/admin/_audit/{e_miss.id}/revert", data={CSRF_FORM_FIELD: csrf_r}).status_code == 404
            # Verify d_ok was NOT corrupted by failed validation revert
            with SessionLocal() as s:
                assert s.get(OpsDoc, d_ok_id).title == "Live"  # type: ignore[union-attr]
        finally:
            deck_rev.close()


def test_passkey_lifecycle_and_session_ownership_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    import flask_deck.routes.auth as auth_routes
    from flask_deck.passkeys import PasskeyCredential
    from flask_deck.sessions import DECK_SID_SESSION_KEY

    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_ops = auth.create_group(name="ops", label="Ops", permissions=frozenset({"docs:view"}))
        u1 = auth.create_user(username="alice", password="AlicePassword1!", group_ids=[g_ops.id])
        u2 = auth.create_user(username="bob", password="BobPassword1!", group_ids=[g_ops.id])
        auth.create_user(username="root", password="RootPassword1!", is_superuser=True)

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "passkey-session-secret-32-bytes!"
        app.config["TESTING"] = True

        pk_store = InMemoryPasskeyStore()
        sess_store = InMemorySessionStore()
        audit_store = InMemoryAuditStore()
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            config=DeckConfig(enable_impersonation=True),
            passkey_store=pk_store,
            session_store=sess_store,
            audit_store=audit_store,
        )

        # Stub WebAuthn ceremonies cleanly at the passkey adapter boundary
        monkeypatch.setattr(
            auth_routes,
            "begin_passkey_registration",
            lambda **kw: ({"challenge": "reg-ch", "rp": {"id": kw["rp_id"]}}, "reg-ch"),
        )
        monkeypatch.setattr(
            auth_routes,
            "complete_passkey_registration",
            lambda **kw: PasskeyCredential(
                credential_id="cred-alice-1",
                user_id=kw["user_id"],
                public_key_b64="cHVibGljLWtleQ==",
                sign_count=0,
                label=kw["label"],
                transports=("internal",),
            ),
        )
        monkeypatch.setattr(
            auth_routes,
            "begin_passkey_authentication",
            lambda **kw: ({"challenge": "auth-ch", "rpId": kw["rp_id"]}, "auth-ch"),
        )

        def _fake_complete_auth(**kw: Any) -> int:
            if kw["credential_json"].get("fail"):
                raise ValueError("bad signature")
            return kw["stored"].sign_count + 1

        monkeypatch.setattr(auth_routes, "complete_passkey_authentication", _fake_complete_auth)

        try:
            c1 = app.test_client()
            csrf1 = _login(c1, "alice", "AlicePassword1!")
            c2 = app.test_client()
            csrf2 = _login(c2, "bob", "BobPassword1!")

            # 1. Passkey registration options + missing payload 400 + valid verify -> stored & audited
            r_ro = c1.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: csrf1})
            assert r_ro.status_code == 200 and r_ro.get_json()["options"]["challenge"] == "reg-ch"
            r_rv_missing = c1.post(
                "/admin/_security/passkeys/register/verify",
                json={},
                headers={CSRF_HEADER_NAME: csrf1},
            )
            assert r_rv_missing.status_code == 400

            c1.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: csrf1})
            r_rv_ok = c1.post(
                "/admin/_security/passkeys/register/verify",
                json={"credential": {"id": "cred-alice-1"}, "label": "MacBook TouchID"},
                headers={CSRF_HEADER_NAME: csrf1},
            )
            assert r_rv_ok.status_code == 200 and r_rv_ok.get_json()["ok"] is True
            assert pk_store.get("cred-alice-1") is not None

            # 2. Passkey login ceremony: options, missing payload 400, unknown cred 404, bad sig 403, valid login 200
            c_anon = app.test_client()
            csrf_a = _extract_csrf(c_anon, "/admin/login")
            assert c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_a}).status_code == 200
            assert c_anon.post("/admin/login/passkey/verify", json={}, headers={CSRF_HEADER_NAME: csrf_a}).status_code == 400

            c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_a})
            assert c_anon.post(
                "/admin/login/passkey/verify",
                json={"credential": {"id": "unknown-cred"}},
                headers={CSRF_HEADER_NAME: csrf_a},
            ).status_code == 404

            c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_a})
            assert c_anon.post(
                "/admin/login/passkey/verify",
                json={"credential": {"id": "cred-alice-1", "fail": True}},
                headers={CSRF_HEADER_NAME: csrf_a},
            ).status_code == 403

            c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_a})
            r_plog = c_anon.post(
                "/admin/login/passkey/verify",
                json={"credential": {"id": "cred-alice-1"}, "next": "/admin/"},
                headers={CSRF_HEADER_NAME: csrf_a},
            )
            assert r_plog.status_code == 200 and r_plog.get_json()["ok"] is True
            stored_after = pk_store.get("cred-alice-1")
            assert stored_after is not None and stored_after.sign_count == 1

            # 3. Bob cannot delete Alice's passkey; Alice deletes it cleanly
            assert c2.post("/admin/_security/passkeys/cred-alice-1/delete", data={CSRF_FORM_FIELD: csrf2}).status_code == 302
            assert pk_store.get("cred-alice-1") is not None
            assert c1.post("/admin/_security/passkeys/cred-alice-1/delete", data={CSRF_FORM_FIELD: csrf1}).status_code == 302
            assert pk_store.get("cred-alice-1") is None

            # 4. Session ownership & revoke-others: Bob cannot revoke Alice's session;
            # Alice's revoke-others revokes her secondary session while preserving current session;
            # Alice revoking her own current session invalidates her next request.
            c1_other = app.test_client()
            _login(c1_other, "alice", "AlicePassword1!")
            with c1.session_transaction() as sess:
                alice_sid = sess[DECK_SID_SESSION_KEY]
            with c1_other.session_transaction() as sess:
                alice_other_sid = sess[DECK_SID_SESSION_KEY]
            with c2.session_transaction() as sess:
                bob_sid = sess[DECK_SID_SESSION_KEY]
            assert alice_sid and alice_other_sid and bob_sid and u1.id != u2.id
            assert c1.get("/admin/_security/sessions").status_code == 200
            assert c1.post("/admin/_security/sessions/revoke-others", data={CSRF_FORM_FIELD: csrf1}).status_code == 302
            assert sess_store.is_active(alice_sid) is True
            assert sess_store.is_active(alice_other_sid) is False
            # Bob's revoke attempt on Alice's session must fail silently (no enumeration) leaving Alice's session active
            assert c2.post(f"/admin/_security/sessions/{alice_sid}/revoke", data={CSRF_FORM_FIELD: csrf2}).status_code == 302
            assert sess_store.is_active(alice_sid) is True
            r_self_rev = c1.post(f"/admin/_security/sessions/{alice_sid}/revoke", data={CSRF_FORM_FIELD: csrf1})
            assert r_self_rev.status_code == 302
            assert sess_store.is_active(alice_sid) is False
            r_after_rev = c1.get("/admin/", follow_redirects=False)
            assert r_after_rev.status_code == 302 and "/login" in r_after_rev.headers["Location"]

            # 5. Impersonation security boundary: an impersonating superuser MUST NOT
            # manage the target user's sessions or register/delete passkeys on their behalf.
            c_root = app.test_client()
            csrf_root = _login(c_root, "root", "RootPassword1!")
            r_imp = c_root.post(
                "/admin/_impersonate/start",
                data={CSRF_FORM_FIELD: csrf_root, "target_user_id": u2.id},
            )
            assert r_imp.status_code == 302
            csrf_imp = _extract_csrf(c_root, "/admin/")
            assert c_root.get("/admin/_security/sessions").status_code == 403
            assert c_root.post(
                f"/admin/_security/sessions/{bob_sid}/revoke",
                data={CSRF_FORM_FIELD: csrf_imp},
            ).status_code == 403
            assert c_root.post(
                "/admin/_security/sessions/revoke-others",
                data={CSRF_FORM_FIELD: csrf_imp},
            ).status_code == 403
            assert c_root.get("/admin/_security/passkeys").status_code == 403
            assert c_root.post(
                "/admin/_security/passkeys/register/options",
                headers={CSRF_HEADER_NAME: csrf_imp},
            ).status_code == 403
            assert c_root.post(
                "/admin/_security/passkeys/register/verify",
                json={"credential": {"id": "imp"}},
                headers={CSRF_HEADER_NAME: csrf_imp},
            ).status_code == 403
            assert c_root.post(
                "/admin/_security/passkeys/cred-alice-1/delete",
                data={CSRF_FORM_FIELD: csrf_imp},
            ).status_code == 403
            assert sess_store.is_active(bob_sid) is True
        finally:
            deck.close()


def test_impersonation_iam_delegation_passkey_mfa_sso_and_approval_reopen_regressions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import base64

    import flask_deck.routes.auth as auth_routes
    from flask_deck.api_keys import build_api_key_record
    from flask_deck.passkeys import PasskeyCredential, SQLAlchemyPasskeyStore
    from flask_deck.sso import (
        SSO_NONCE_KEY,
        SSO_STATE_KEY,
        SSO_VERIFIER_KEY,
        _verify_jwk_signature,
    )

    class _GovOpsDocView(ModelView):
        model = OpsDoc
        slug = "docs"
        approval_required = ("edit",)
        soft_delete_column = "deleted_at"

        def validate(self, data: Any, *, obj: Any = None) -> dict[str, list[str]]:
            _ = obj
            if data.get("title") == "BOOM_ON_APPROVE":
                return {"title": ["Rejected during approval execution"]}
            return {}

    # 1. Impersonation boundaries, delegated IAM escalation guard, API key owner enforcement,
    #    passkey duplicate/rate-limit, MFA enable/disable guards, approval reopen & SQL dialect save
    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        with SessionLocal() as s:
            d1 = OpsDoc(title="Original")
            s.add(d1)
            s.commit()
            d1_id = d1.id

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_review = auth.create_group(
            name="reviewer_iam",
            label="Reviewer+IAM",
            permissions=frozenset(
                {
                    "docs:view",
                    "docs:edit",
                    "approvals:view",
                    "approvals:review",
                    "iam:manage",
                    "api_keys:manage",
                    "sql:query",
                }
            ),
        )
        g_wild = auth.create_group(
            name="wild_ops",
            label="Wildcard Ops",
            permissions=frozenset({"*"}),
        )
        g_plain = auth.create_group(
            name="plain_keys",
            label="Plain Keys",
            permissions=frozenset({"docs:view", "api_keys:manage"}),
        )

        root = auth.create_user(username="root", password="RootPassword1!", is_superuser=True)
        delegate = auth.create_user(
            username="delegate",
            password="DelegatePassword1!",
            is_superuser=False,
            group_ids=[g_review.id],
        )
        wild_user = auth.create_user(
            username="wildadmin",
            password="WildPassword1!",
            is_superuser=False,
            group_ids=[g_wild.id],
        )
        plain_user = auth.create_user(
            username="plainuser",
            password="PlainPassword1!",
            is_superuser=False,
            group_ids=[g_plain.id],
        )
        demoted_user = auth.create_user(
            username="demoted",
            password="DemotedPassword1!",
            is_superuser=True,
            tenant_id="tenant-alpha",
        )

        api_keys = InMemoryAPIKeyStore()
        approvals = InMemoryApprovalStore()
        mfa_store = InMemoryMFAStore()
        pk_store = SQLAlchemyPasskeyStore(eng)
        saved_queries = InMemorySavedQueryStore()

        # Issue API keys for wild_user (later deleted) and demoted_user (later demoted)
        demoted_tok, demoted_key_rec = build_api_key_record(
            name="demoted-k",
            owner_id=demoted_user.id,
            owner_name="demoted",
            scopes=("*",),
            is_superuser=True,
            roles=("*",),
        )
        api_keys.create(demoted_key_rec)

        plain_tok, plain_key_rec = build_api_key_record(
            name="plain-k",
            owner_id=plain_user.id,
            owner_name="plainuser",
            scopes=("docs:view",),
            roles=("plain_keys",),
        )
        api_keys.create(plain_key_rec)

        app = Flask(__name__)
        app.config["SECRET_KEY"] = "deep-bug-hunt-auth-secret-32b!!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            config=DeckConfig(
                enable_impersonation=True,
                impersonate_read_only=False,
                enable_rest_api=True,
                enable_sql_console=True,
            ),
            api_key_store=api_keys,
            approval_store=approvals,
            mfa_store=mfa_store,
            passkey_store=pk_store,
            saved_query_store=saved_queries,
            rate_limit_store=LoginRateLimiter(max_attempts=2, window_seconds=60, lockout_seconds=60),
            audit_store=InMemoryAuditStore(),
        )
        deck.register(_GovOpsDocView)

        monkeypatch.setattr(
            auth_routes,
            "begin_passkey_registration",
            lambda **kw: ({"challenge": "r-ch", "rp": {"id": kw["rp_id"]}}, "r-ch"),
        )
        monkeypatch.setattr(
            auth_routes,
            "complete_passkey_registration",
            lambda **kw: PasskeyCredential(
                credential_id="dup-cred-1",
                user_id=kw["user_id"],
                public_key_b64="cGs=",
                sign_count=0,
                label=kw["label"],
            ),
        )
        monkeypatch.setattr(
            auth_routes,
            "begin_passkey_authentication",
            lambda **kw: ({"challenge": "a-ch", "rpId": kw["rp_id"]}, "a-ch"),
        )
        monkeypatch.setattr(
            auth_routes,
            "complete_passkey_authentication",
            lambda **kw: (_ for _ in ()).throw(ValueError("bad sig")),
        )

        try:
            c_root = app.test_client()
            csrf_root = _login(c_root, "root", "RootPassword1!")
            c_del = app.test_client()
            csrf_del = _login(c_del, "delegate", "DelegatePassword1!")
            c_plain = app.test_client()
            _login(c_plain, "plainuser", "PlainPassword1!")

            # A. Impersonation boundaries under impersonate_read_only=False
            r_imp = c_root.post(
                "/admin/_impersonate/start",
                data={CSRF_FORM_FIELD: csrf_root, "target_user_id": delegate.id},
            )
            assert r_imp.status_code == 302
            csrf_imp = _extract_csrf(c_root, "/admin/")

            # Impersonating superuser is blocked from IAM admin & API keys GET
            assert c_root.get("/admin/_security/users").status_code == 403
            assert c_root.get("/admin/_security/groups").status_code == 403
            assert c_root.get("/admin/_security/api-keys").status_code == 403

            # Editing a governed model while impersonating records _impersonator_id = root.id
            r_imp_edit = c_root.post(
                f"/admin/docs/{d1_id}/edit",
                data={CSRF_FORM_FIELD: csrf_imp, "title": "Impersonated Edit", "_approval_reason": "test"},
            )
            assert r_imp_edit.status_code == 302
            imp_reqs = [r for r in approvals.list_requests(status="pending") if r.record_pk == str(d1_id)]
            assert len(imp_reqs) == 1
            imp_req = imp_reqs[0]
            assert imp_req.payload.get("_impersonator_id") == root.id

            # Impersonator cannot approve or reject while impersonating
            assert c_root.post(f"/admin/_approvals/{imp_req.id}/approve", data={CSRF_FORM_FIELD: csrf_imp}).status_code == 403
            assert c_root.post(f"/admin/_approvals/{imp_req.id}/reject", data={CSRF_FORM_FIELD: csrf_imp}).status_code == 403

            # Even AFTER stopping impersonation, original actor (root) is blocked from self-approving!
            assert c_root.post("/admin/_impersonate/stop", data={CSRF_FORM_FIELD: csrf_imp}).status_code == 302
            csrf_root2 = _extract_csrf(c_root, "/admin/")
            assert c_root.post(f"/admin/_approvals/{imp_req.id}/approve", data={CSRF_FORM_FIELD: csrf_root2}).status_code == 403

            # B. Delegated iam:manage admin CANNOT modify/deactivate/reset/delete a non-superuser with '*'
            assert c_del.post(
                f"/admin/_security/users/{wild_user.id}/update",
                data={CSRF_FORM_FIELD: csrf_del, "display_name": "Hacked"},
            ).status_code == 403
            assert c_del.post(
                f"/admin/_security/users/{wild_user.id}/reset-password",
                data={CSRF_FORM_FIELD: csrf_del, "new_password": "NewPassword9!"},
            ).status_code == 403
            assert c_del.post(
                f"/admin/_security/users/{wild_user.id}/delete",
                data={CSRF_FORM_FIELD: csrf_del},
            ).status_code == 403
            assert c_del.post(
                "/admin/_security/users/bulk",
                data={CSRF_FORM_FIELD: csrf_del, "action": "deactivate", "user_ids": [wild_user.id]},
            ).status_code == 403
            assert auth.get_user_record(wild_user.id).is_active is True  # type: ignore[union-attr]

            # C. Deleting IAM user revokes their API keys; deleted/demoted owner's key is enforced live
            assert c_root.post(
                f"/admin/_security/users/{plain_user.id}/delete",
                data={CSRF_FORM_FIELD: csrf_root2},
            ).status_code == 302
            assert api_keys.get(plain_key_rec.id).revoked_at is not None  # type: ignore[union-attr]
            assert app.test_client().get(
                "/admin/_api/v1/docs", headers={"Authorization": f"Bearer {plain_tok}"}
            ).status_code == 401

            # Demote demoted_user (remove superuser, zero permissions) -> stale superuser key loses access!
            auth.update_user(demoted_user.id, is_superuser=False, group_ids=[], direct_permissions=frozenset())
            r_demoted = app.test_client().get(
                "/admin/_api/v1/docs", headers={"Authorization": f"Bearer {demoted_tok}"}
            )
            assert r_demoted.status_code == 403

            # Non-superuser creating an API key with no groups does NOT silently get ('viewer',)
            roleless = auth.create_user(
                username="roleless",
                password="RolelessPassword1!",
                is_superuser=False,
                direct_permissions=frozenset({"api_keys:manage"}),
            )
            c_rl = app.test_client()
            csrf_rl = _login(c_rl, "roleless", "RolelessPassword1!")
            assert c_rl.post(
                "/admin/_security/api-keys/create",
                data={CSRF_FORM_FIELD: csrf_rl, "name": "k-roleless", "scopes": "docs:view", "ttl_days": "30"},
            ).status_code == 302
            rl_keys = api_keys.list_keys(owner_id=roleless.id)
            assert len(rl_keys) == 1 and rl_keys[0].roles == ()

            # D. Duplicate passkey credential rejected (ValueError & HTTP 409) + login verify rate-limit & JSON guard
            c_del.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: csrf_del})
            assert c_del.post(
                "/admin/_security/passkeys/register/verify",
                json={"credential": {"id": "dup-cred-1"}, "label": "Key A"},
                headers={CSRF_HEADER_NAME: csrf_del},
            ).status_code == 200
            with pytest.raises(ValueError, match="already registered"):
                pk_store.add(
                    PasskeyCredential(
                        credential_id="dup-cred-1",
                        user_id=root.id,
                        label="Dup Key",
                        public_key_b64="cGs=",
                    )
                )
            c_root.post("/admin/_security/passkeys/register/options", headers={CSRF_HEADER_NAME: csrf_root2})
            assert c_root.post(
                "/admin/_security/passkeys/register/verify",
                json={"credential": {"id": "dup-cred-1"}, "label": "Hijack"},
                headers={CSRF_HEADER_NAME: csrf_root2},
            ).status_code == 409

            c_anon = app.test_client()
            csrf_anon = _extract_csrf(c_anon, "/admin/login")
            # Non-object JSON rejected cleanly with 400
            assert c_anon.post(
                "/admin/login/passkey/verify",
                data="[]",
                content_type="application/json",
                headers={CSRF_HEADER_NAME: csrf_anon},
            ).status_code == 400
            # Repeated failed passkey verifications hit 429 rate-limit
            for _ in range(2):
                c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_anon})
                assert c_anon.post(
                    "/admin/login/passkey/verify",
                    json={"credential": {"id": "dup-cred-1"}},
                    headers={CSRF_HEADER_NAME: csrf_anon},
                ).status_code == 403
            c_anon.post("/admin/login/passkey/options", headers={CSRF_HEADER_NAME: csrf_anon})
            assert c_anon.post(
                "/admin/login/passkey/verify",
                json={"credential": {"id": "dup-cred-1"}},
                headers={CSRF_HEADER_NAME: csrf_anon},
            ).status_code == 429

            # E. MFA enable refuses overwrite when already enabled; disable rate-limits wrong codes
            assert c_del.get("/admin/_security/mfa").status_code == 200
            with c_del.session_transaction() as sess:
                orig_sec = sess.get("_deck_mfa_setup_secret")
            assert orig_sec
            assert c_del.post(
                "/admin/_security/mfa",
                data={"action": "enable", "code": compute_totp(orig_sec), CSRF_FORM_FIELD: csrf_del},
            ).status_code == 200
            # Re-submitting enable must NOT replace the active secret
            with c_del.session_transaction() as sess:
                sess["_deck_mfa_setup_secret"] = generate_totp_secret()
            c_del.post(
                "/admin/_security/mfa",
                data={"action": "enable", "code": "123456", CSRF_FORM_FIELD: csrf_del},
            )
            assert mfa_store.get(delegate.id).secret == orig_sec  # type: ignore[union-attr]
            # Repeated bad disable codes lock out MFA disable even on valid code
            for _ in range(2):
                c_del.post(
                    "/admin/_security/mfa",
                    data={"action": "disable", "code": "000000", CSRF_FORM_FIELD: csrf_del},
                )
            r_dis_locked = c_del.post(
                "/admin/_security/mfa",
                data={"action": "disable", "code": compute_totp(orig_sec, timestamp=time.time() + 30), CSRF_FORM_FIELD: csrf_del},
            )
            assert r_dis_locked.status_code == 200
            assert "Too many failed MFA attempts" in r_dis_locked.get_data(as_text=True)
            assert mfa_store.get(delegate.id) is not None

            # F. Approval execution failure rolls back & reopens request to 'pending'; inactive requester blocked
            req_boom = approvals.create(
                make_approval_request(
                    model_slug="docs",
                    model_label="Doc",
                    operation="edit",
                    record_pk=str(d1_id),
                    record_repr="Original",
                    payload={"values": {"title": "BOOM_ON_APPROVE"}},
                    diff={"title": {"old": "Original", "new": "BOOM_ON_APPROVE"}},
                    reason="Will fail validation on execute",
                    requester_id=delegate.id,
                    requester_name="delegate",
                )
            )
            assert c_root.post(
                f"/admin/_approvals/{req_boom.id}/approve",
                data={CSRF_FORM_FIELD: csrf_root2},
            ).status_code == 302
            assert approvals.get(req_boom.id).status == "pending"  # type: ignore[union-attr]

            # Deactivating requester blocks execution when reviewer tries to approve
            req_inact = approvals.create(
                make_approval_request(
                    model_slug="docs",
                    model_label="Doc",
                    operation="edit",
                    record_pk=str(d1_id),
                    record_repr="Original",
                    payload={"values": {"title": "Should Not Apply"}},
                    diff={"title": {"old": "Original", "new": "Should Not Apply"}},
                    reason="Requester deactivated",
                    requester_id=delegate.id,
                    requester_name="delegate",
                )
            )
            auth.update_user(delegate.id, is_active=False)
            assert c_root.post(
                f"/admin/_approvals/{req_inact.id}/approve",
                data={CSRF_FORM_FIELD: csrf_root2},
            ).status_code == 302
            assert approvals.get(req_inact.id).status == "pending"  # type: ignore[union-attr]
            with SessionLocal() as s:
                assert s.get(OpsDoc, d1_id).title == "Original"  # type: ignore[union-attr]

            # G. sql_save validates against target dialect (PG dollar-quoted attack rejected on SQLite)
            assert c_root.post(
                "/admin/_sql/save",
                data={
                    "name": "BadSQLiteDollar",
                    "sql": "SELECT $q$; DROP TABLE ops_docs$q$",
                    CSRF_FORM_FIELD: csrf_root2,
                },
            ).status_code == 302
            assert saved_queries.list_queries() == []
            _ = c_plain
        finally:
            deck.close()

    # 2. SSO: superuser require_mfa_for_superusers preserves tenant_id/metadata without redirect loop,
    #    plus malformed JWK, exp=inf, and userinfo.sub mismatch defenses.
    def _b64u(obj: dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    with pytest.raises(PermissionError):
        _verify_jwk_signature({"alg": "RS256", "kid": "k1"}, b"hdr.pay", b"sig", [{"kid": "k1", "kty": "RSA"}])

    cfg_no_sig = OIDCProviderConfig.okta(
        domain="https://okta.example.test",
        client_id="cid",
        client_secret="csec",
        require_id_token_signature=False,
    )
    provider_unit = OIDCAuthProvider(
        providers=[cfg_no_sig],
        roles=[Role("admin", permissions=frozenset({"*"}))],
        http_transport=lambda method, url, hdrs, body, to: (
            (200, {"access_token": "tok", "id_token": f"{_b64u({'alg': 'RS256'})}.{_b64u({'sub': 'sub-1', 'nonce': 'n1', 'aud': 'cid'})}.sig"})
            if "token" in url
            else (200, {"sub": "sub-DIFFERENT", "email": "a@example.test", "email_verified": True})
        ),
    )
    # Non-finite exp claim rejected as PermissionError (not OverflowError)
    inf_payload = base64.urlsafe_b64encode(b'{"exp": 1e309}').rstrip(b"=").decode("ascii")
    inf_tok = f"{_b64u({'alg': 'RS256'})}.{inf_payload}.sig"
    with pytest.raises(PermissionError, match="invalid exp"):
        provider_unit._verify_id_token(cfg_no_sig, inf_tok, expected_nonce="", jwks_uri="")

    # Mismatched userinfo.sub vs id_token.sub rejected per OIDC Core §5.3.4
    app_oidc = Flask(__name__)
    app_oidc.config["SECRET_KEY"] = "oidc-sub-check-secret-32-bytes!!"
    with app_oidc.test_request_context("/admin/login/sso/okta/callback"):
        from flask import session as flask_session

        flask_session[SSO_STATE_KEY] = "okta:st1"
        flask_session[SSO_VERIFIER_KEY] = "v1"
        flask_session[SSO_NONCE_KEY] = "n1"
        with pytest.raises(PermissionError, match="subject does not match"):
            provider_unit.complete_callback("okta", code="c1", state="st1", redirect_uri="https://app/cb")

    # SSO superuser with require_mfa_for_superusers=True: MFA challenge completes & preserves tenant_id/metadata
    with sqlite_memory_engine() as eng2:
        OpsBase.metadata.create_all(eng2)
        SessionLocal2 = sessionmaker(bind=eng2, autoflush=False, expire_on_commit=False)
        sso_super = DeckUser(
            id="sso:okta:super-1",
            username="sso_super",
            display_name="SSO Super",
            roles=("admin",),
            is_superuser=True,
            tenant_id="tenant-sso-99",
            metadata=MappingProxyType({"dept": "secops"}),
        )
        sso_auth2 = OIDCAuthProvider(
            providers=[cfg_no_sig],
            roles=[Role("admin", permissions=frozenset({"*"}))],
            http_transport=lambda *_a: (200, {}),
        )
        sso_auth2.complete_callback = lambda prov, *, code, state, redirect_uri: (sso_super, "/admin/")  # type: ignore[method-assign]
        mfa_sec2 = generate_totp_secret()
        mfa_store2 = InMemoryMFAStore()
        mfa_store2.save(MFAEnrollment(user_id=sso_super.id, secret=mfa_sec2, enabled=True))

        app_sso2 = Flask(__name__)
        app_sso2.config["SECRET_KEY"] = "sso-super-mfa-secret-32-bytes!!!"
        app_sso2.config["TESTING"] = True
        deck_sso2 = Deck(
            app_sso2,
            session_factory=SessionLocal2,
            engine=eng2,
            auth=sso_auth2,
            config=DeckConfig(require_mfa_for_superusers=True),
            mfa_store=mfa_store2,
            audit_store=False,
        )
        try:
            cs2 = app_sso2.test_client()
            # Simulate an already-logged-in SSO session whose MFA is not yet verified -> deck before_request redirects cleanly to /login/mfa
            r_cb2 = cs2.get("/admin/login/sso/okta/callback?code=c&state=s")
            assert r_cb2.status_code == 302 and "/login/mfa" in r_cb2.headers["Location"]
            csrf_m2 = _extract_csrf(cs2, "/admin/login/mfa")
            r_m2 = cs2.post(
                "/admin/login/mfa",
                data={"code": compute_totp(mfa_sec2), CSRF_FORM_FIELD: csrf_m2},
            )
            assert r_m2.status_code == 302 and r_m2.headers["Location"].endswith("/admin/")
            assert cs2.get("/admin/").status_code == 200
            with cs2.session_transaction() as sess:
                stored_sso = sess.get("_deck_sso_user")
                assert isinstance(stored_sso, dict)
                assert stored_sso.get("tenant_id") == "tenant-sso-99"
                assert stored_sso.get("metadata") == {"dept": "secops"}
                # Simulate mid-session require_mfa_for_superusers challenge (drop MFA_VERIFIED_KEY)
                sess.pop("_deck_mfa_verified", None)
            r_rechal = cs2.get("/admin/", follow_redirects=False)
            assert r_rechal.status_code == 302 and "/login/mfa" in r_rechal.headers["Location"]
            csrf_m3 = _extract_csrf(cs2, "/admin/login/mfa")
            r_m3 = cs2.post(
                "/admin/login/mfa",
                data={"code": compute_totp(mfa_sec2, timestamp=time.time() + 30), CSRF_FORM_FIELD: csrf_m3},
            )
            assert r_m3.status_code == 302 and r_m3.headers["Location"].endswith("/admin/")
            assert cs2.get("/admin/").status_code == 200
        finally:
            deck_sso2.close()


def test_approved_execution_apikey_guards_version_conflict_and_inline_media_scope() -> None:
    from datetime import timedelta

    from flask_deck.api_keys import build_api_key_record

    mem_store = MemoryFileStorage()

    class _ScopedAttInline(InlineModelView):
        model = OpsAttachment
        fk_column = "doc_id"
        columns = ("label", "blob_key")
        file_fields = MappingProxyType({"blob_key": FileFieldConfig(storage=mem_store, kind="file")})

        def scope_query(self, stmt: Any, user: Any, parent: Any = None) -> Any:
            _ = (user, parent)
            return stmt.where(OpsAttachment.label != "PRIVATE_ATT")

    class _VerDocView(ModelView):
        model = OpsDoc
        slug = "docs"
        soft_delete_column = "deleted_at"
        version_column = "version"
        inlines = (_ScopedAttInline,)

        def can_delete_record(self, obj: Any, user: Any) -> bool:
            _ = user
            return not obj.restricted

    with sqlite_memory_engine() as eng:
        OpsBase.metadata.create_all(eng)
        SL = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        mem_store.save(b"pub", key="att/public.txt", content_type="text/plain")
        mem_store.save(b"priv", key="att/private.txt", content_type="text/plain")
        with SL() as s:
            d_live = OpsDoc(title="Live Doc", version=2)
            d_trash = OpsDoc(title="Trashed Doc", deleted_at=datetime.now(timezone.utc))
            d_rest = OpsDoc(title="Locked Doc", restricted=True)
            s.add_all([d_live, d_trash, d_rest])
            s.flush()
            a_pub = OpsAttachment(doc_id=d_live.id, label="PUBLIC_ATT", blob_key="att/public.txt")
            a_priv = OpsAttachment(doc_id=d_live.id, label="PRIVATE_ATT", blob_key="att/private.txt")
            s.add_all([a_pub, a_priv])
            s.commit()
            d_live_id, d_trash_id, d_rest_id = d_live.id, d_trash.id, d_rest.id
            a_pub_id, a_priv_id = a_pub.id, a_priv.id

        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        g_ed = auth.create_group(name="ed", label="Ed", permissions=frozenset({"docs:view", "docs:edit", "docs:delete"}))
        auth.create_user(username="root", password="RootPassword1!", is_superuser=True)
        u_owner = auth.create_user(username="kowner", password="OwnerPassword1!", is_superuser=True, group_ids=[g_ed.id])

        keys = InMemoryAPIKeyStore()
        _, rec_revoked = build_api_key_record(
            name="revoked", owner_id=u_owner.id, owner_name="kowner", scopes=("*",), is_superuser=True
        )
        keys.create(rec_revoked)
        keys.revoke(rec_revoked.id)

        from dataclasses import replace as dc_replace

        _, rec_expired_raw = build_api_key_record(
            name="expired",
            owner_id=u_owner.id,
            owner_name="kowner",
            scopes=("*",),
            is_superuser=True,
        )
        rec_expired = dc_replace(
            rec_expired_raw,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        keys.create(rec_expired)

        _, rec_active = build_api_key_record(
            name="active", owner_id=u_owner.id, owner_name="kowner", scopes=("*",), is_superuser=True
        )
        keys.create(rec_active)

        approvals = InMemoryApprovalStore()
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "exec-guards-secret-32-bytes-ok!"
        app.config["TESTING"] = True
        deck = Deck(
            app,
            session_factory=SL,
            engine=eng,
            auth=auth,
            api_key_store=keys,
            approval_store=approvals,
            audit_store=InMemoryAuditStore(),
        )
        deck.register(_VerDocView)
        try:
            c = app.test_client()
            csrf = _login(c, "root", "RootPassword1!")

            # 1. Inline media route re-evaluates inline.scope_query(stmt, user, parent_obj)
            inl_slug = deck.get_view("docs").inline_views[0].meta.slug
            assert c.get(f"/admin/_media/docs/_inline/{inl_slug}/blob_key/{a_pub_id}").status_code == 200
            assert c.get(f"/admin/_media/docs/_inline/{inl_slug}/blob_key/{a_priv_id}").status_code == 404

            # 2. _execute_approved_request guards: revoked key, expired key, missing key, version conflict, trashed, locked delete, demoted & deactivated owner
            def _queue(op: str, pk: str, req_id: str, actor_type: str, payload: dict[str, Any]) -> str:
                r = approvals.create(
                    make_approval_request(
                        model_slug="docs",
                        model_label="Doc",
                        operation=op,
                        record_pk=pk,
                        record_repr="Doc",
                        payload=payload,
                        diff={},
                        reason="test",
                        requester_id=req_id,
                        requester_name="req",
                        actor_type=actor_type,
                    )
                )
                return r.id

            # Revoked API key
            id_rev = _queue("edit", str(d_live_id), f"apikey:{rec_revoked.id}", "api_key", {"values": {"title": "X"}})
            assert c.post(f"/admin/_approvals/{id_rev}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_rev).status == "pending"  # type: ignore[union-attr]

            # Expired API key
            id_exp = _queue("edit", str(d_live_id), f"apikey:{rec_expired.id}", "api_key", {"values": {"title": "X"}})
            assert c.post(f"/admin/_approvals/{id_exp}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_exp).status == "pending"  # type: ignore[union-attr]

            # Deleted/unknown API key
            id_miss = _queue("edit", str(d_live_id), "apikey:does-not-exist", "api_key", {"values": {"title": "X"}})
            assert c.post(f"/admin/_approvals/{id_miss}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_miss).status == "pending"  # type: ignore[union-attr]

            # Version conflict during edit approval
            id_ver = _queue(
                "edit",
                str(d_live_id),
                f"apikey:{rec_active.id}",
                "api_key",
                {"values": {"title": "Stale"}, "expected_version": "1"},
            )
            assert c.post(f"/admin/_approvals/{id_ver}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_ver).status == "pending"  # type: ignore[union-attr]

            # Soft-deleted record during edit approval
            id_tr = _queue("edit", str(d_trash_id), f"apikey:{rec_active.id}", "api_key", {"values": {"title": "X"}})
            assert c.post(f"/admin/_approvals/{id_tr}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_tr).status == "pending"  # type: ignore[union-attr]

            # can_delete_record=False during delete approval
            id_ld = _queue("delete", str(d_rest_id), f"apikey:{rec_active.id}", "api_key", {"force": False})
            assert c.post(f"/admin/_approvals/{id_ld}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_ld).status == "pending"  # type: ignore[union-attr]

            # Demoted API key owner loses access at execution time
            auth.update_user(u_owner.id, is_superuser=False, group_ids=[], direct_permissions=frozenset())
            id_dem = _queue("edit", str(d_live_id), f"apikey:{rec_active.id}", "api_key", {"values": {"title": "Dem"}})
            assert c.post(f"/admin/_approvals/{id_dem}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_dem).status == "pending"  # type: ignore[union-attr]

            # Deactivated API key owner blocked at execution time
            auth.update_user(u_owner.id, is_active=False)
            id_deact = _queue("edit", str(d_live_id), f"apikey:{rec_active.id}", "api_key", {"values": {"title": "Deact"}})
            assert c.post(f"/admin/_approvals/{id_deact}/approve", data={CSRF_FORM_FIELD: csrf}).status_code == 302
            assert approvals.get(id_deact).status == "pending"  # type: ignore[union-attr]
        finally:
            deck.close()
