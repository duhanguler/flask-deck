from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from flask_deck import (
    AuditEntry,
    Deck,
    DeckUser,
    InlineModelView,
    InMemoryApprovalStore,
    InMemoryAuditStore,
    InMemoryRecordNoteStore,
    InMemorySavedViewStore,
    ModelView,
    RBACAuthProvider,
    RecordNote,
    Role,
    SavedViewRecord,
    SQLAlchemyApprovalStore,
    SQLAlchemyAuditStore,
    SQLAlchemyRecordNoteStore,
    SQLAlchemySavedViewStore,
    action,
    make_approval_request,
    render_safe_markdown,
    run_security_audit,
)
from flask_deck.cli import deck_cli
from flask_deck.security import CSRF_FORM_FIELD, CSRF_HEADER_NAME
from tests.conftest import extract_csrf, login_as

_INLINE_STYLE_RE = re.compile(r"\sstyle\s*=", re.IGNORECASE)
_INLINE_HANDLER_RE = re.compile(r"\son(?:click|change|submit|input|load)\s*=", re.IGNORECASE)


class M3Base(DeclarativeBase):
    pass


class GovOrder(M3Base):
    __tablename__ = "m3_orders"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(sa.String(32), default="pending", nullable=False)
    is_urgent: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), default=Decimal("100.00"))
    api_token: Mapped[str | None] = mapped_column(sa.String(120), nullable=True)
    version: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True), nullable=True)

    lines: Mapped[list[GovLineItem]] = relationship(
        back_populates="order", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return f"Order {self.reference}"


class GovLineItem(M3Base):
    __tablename__ = "m3_line_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(sa.ForeignKey("m3_orders.id"), nullable=False)
    sku: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    qty: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    order: Mapped[GovOrder] = relationship(back_populates="lines")


def _assert_strict_csp(resp: Any) -> None:
    html = resp.get_data(as_text=True)
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "nonce-" in csp
    assert not _INLINE_STYLE_RE.search(html), "Inline style= breaks strict Nonce CSP"
    assert not _INLINE_HANDLER_RE.search(html), "Inline on*= handler breaks strict Nonce CSP"
    assert "<style" not in html.lower(), "<style> tag breaks strict Nonce CSP"


def _make_gov_rbac() -> RBACAuthProvider:
    return RBACAuthProvider(
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="maker",
                permissions=frozenset(
                    {
                        "gov-orders:view",
                        "gov-orders:create",
                        "gov-orders:edit",
                        "gov-orders:delete",
                        "gov-orders:action:refund_orders",
                        "approvals:view",
                        "approvals:review",
                    }
                ),
            ),
            Role(
                name="checker",
                permissions=frozenset(
                    {
                        "gov-orders:view",
                        "approvals:view",
                        "approvals:review",
                        "audit:view",
                    }
                ),
            ),
            Role(
                name="support",
                permissions=frozenset(
                    {
                        "gov-orders:view",
                        "notes:write",
                        "audit:view",
                    }
                ),
                masked_fields={"gov-orders": frozenset({"amount"})},
                hidden_fields={"gov-orders": frozenset({"api_token"})},
            ),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-adm", username="admin", roles=("admin",), is_superuser=True),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-maker", username="maker", roles=("maker",)),
                password="maker-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-checker", username="checker", roles=("checker",)),
                password="checker-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(id="u-support", username="support", roles=("support",)),
                password="support-password",
            ),
        ],
    )


def _setup_sqlite_deck(
    tmp_path: Path,
    *,
    hash_chain: bool = False,
    approval_required: Any = True,
    version_column: str | None = "version",
    with_inline: bool = False,
) -> tuple[Flask, Deck, sa.Engine, sessionmaker[Any]]:
    db_file = tmp_path / "m3_gov.sqlite3"
    eng = sa.create_engine(
        f"sqlite:///{db_file.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    try:
        M3Base.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)

        with SessionLocal() as s:
            s.add(
                GovOrder(
                    reference="ORD-100",
                    status="pending",
                    amount=Decimal("250.00"),
                    api_token="tok_live_secret_999",
                    version=1,
                )
            )
            s.commit()

        class GovLineItemInline(InlineModelView):
            model = GovLineItem
            fk_column = "order_id"

        class GovOrderView(ModelView):
            model = GovOrder
            columns = ("id", "reference", "status", "is_urgent", "amount", "version")
            searchable_columns = ("reference", "status")
            filterable_columns = ("status", "amount", "is_urgent")
            inline_editable_columns = ("is_urgent",)
            form_columns = ("reference", "status", "is_urgent", "amount", "api_token", "version")
            inlines = (GovLineItemInline,) if with_inline else ()

            @action(
                name="refund_orders",
                label="Refund Orders",
                require_approval=True,
            )
            def refund_orders(self, records: list[GovOrder], form: Any, user: Any) -> str:
                for rec in records:
                    rec.status = "refunded"
                return f"Refunded {len(records)} order(s)"

        view = GovOrderView()
        view.approval_required = approval_required
        view.version_column = version_column

        app = Flask(__name__)
        app.secret_key = "m3-governance-test-secret"
        app.config["TESTING"] = True

        audit_store = SQLAlchemyAuditStore(eng, hash_chain=hash_chain)
        approval_store = SQLAlchemyApprovalStore(eng)
        saved_view_store = SQLAlchemySavedViewStore(eng)
        note_store = SQLAlchemyRecordNoteStore(eng)

        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=_make_gov_rbac(),
            audit_store=audit_store,
            approval_store=approval_store,
            saved_view_store=saved_view_store,
            note_store=note_store,
            url_prefix="/admin",
        )
        deck.register(view)
        return app, deck, eng, SessionLocal
    except Exception:
        eng.dispose()
        raise


def test_four_eyes_maker_checker_create_edit_delete_action_and_bypass_guards(
    tmp_path: Path,
) -> None:
    def _approval_policy(
        user: DeckUser | None,
        op: str,
        obj: GovOrder | None = None,
        payload: Any = None,
    ) -> bool:
        return True

    app, deck, eng, SessionLocal = _setup_sqlite_deck(
        tmp_path,
        approval_required=_approval_policy,
        version_column=None,
    )
    events: list[str] = []
    deck.events.subscribe("*", lambda ev: events.append(ev.name))

    try:
        maker_client = app.test_client()
        checker_client = app.test_client()
        login_as(maker_client, "maker", "maker-password")
        login_as(checker_client, "checker", "checker-password")

        # 1. SAVEPOINT validation blocks invalid create cleanly (does NOT queue approval)
        form_get = maker_client.get("/admin/gov-orders/new")
        assert form_get.status_code == 200
        assert "Four-Eyes Approval Required" in form_get.get_data(as_text=True)
        _assert_strict_csp(form_get)
        csrf_m = extract_csrf(form_get.get_data(as_text=True))

        bad_resp = maker_client.post(
            "/admin/gov-orders/new",
            data={
                CSRF_FORM_FIELD: csrf_m,
                "reference": "ORD-100",  # duplicate UNIQUE constraint
                "status": "pending",
                "amount": "99.00",
                "version": "1",
            },
        )
        assert bad_resp.status_code == 200
        assert deck.approval_store is not None
        assert deck.approval_store.pending_count() == 0

        # 2. Valid create queues into ApprovalQueue without writing DB yet
        ok_queue = maker_client.post(
            "/admin/gov-orders/new",
            data={
                CSRF_FORM_FIELD: csrf_m,
                "reference": "ORD-200",
                "status": "pending",
                "amount": "450.00",
                "api_token": "tok_top_secret_123",
                "version": "1",
                "approval_reason": "Large customer manual order",
            },
            follow_redirects=False,
        )
        assert ok_queue.status_code in {302, 303}
        reqs = deck.approval_store.list_requests(status="pending")
        assert len(reqs) == 1
        req_create = reqs[0]
        assert req_create.operation == "create"
        assert req_create.requester_id == "u-maker"
        assert req_create.diff["reference"]["new"] == "ORD-200"
        assert "api_token" not in req_create.diff  # sensitive field never writable from form

        with SessionLocal() as s:
            assert s.scalar(sa.select(GovOrder).where(GovOrder.reference == "ORD-200")) is None

        # 3. Four-eyes self-approval & self-reject are strictly blocked (403)
        q_maker = maker_client.get("/admin/_approvals")
        assert q_maker.status_code == 200
        assert "Awaiting peer reviewer" in q_maker.get_data(as_text=True)
        _assert_strict_csp(q_maker)
        csrf_q_m = extract_csrf(q_maker.get_data(as_text=True))

        self_approve = maker_client.post(
            f"/admin/_approvals/{req_create.id}/approve",
            data={CSRF_FORM_FIELD: csrf_q_m, "review_note": "self approve"},
        )
        assert self_approve.status_code == 403
        self_reject = maker_client.post(
            f"/admin/_approvals/{req_create.id}/reject",
            data={CSRF_FORM_FIELD: csrf_q_m, "review_note": "self reject"},
        )
        assert self_reject.status_code == 403

        # 4. Checker approves -> record persists + dual-actor audit recorded
        q_checker = checker_client.get("/admin/_approvals")
        assert q_checker.status_code == 200
        csrf_c = extract_csrf(q_checker.get_data(as_text=True))
        app_resp = checker_client.post(
            f"/admin/_approvals/{req_create.id}/approve",
            data={CSRF_FORM_FIELD: csrf_c, "review_note": "Verified PO #77"},
            follow_redirects=False,
        )
        assert app_resp.status_code in {302, 303}

        with SessionLocal() as s:
            ord200 = s.scalar(sa.select(GovOrder).where(GovOrder.reference == "ORD-200"))
            assert ord200 is not None
            assert ord200.amount == Decimal("450.00")

        assert deck.audit_store is not None
        entries, _ = deck.audit_store.list_entries(model_slug="gov-orders", action="create")
        assert entries[0].actor_id == "u-maker"
        assert entries[0].metadata["approved_by"] == "u-checker"
        assert entries[0].metadata["approval_id"] == req_create.id
        assert "approval.requested" in events
        assert "approval.approved" in events

        # Atomic CAS second resolve returns None even for another user
        assert (
            deck.approval_store.resolve(
                req_create.id,
                status="approved",
                reviewer_id="u-adm",
                reviewer_name="admin",
            )
            is None
        )

        # 5. Bypass surfaces closed: quick-edit and bulk-delete do NOT bypass approval
        quick_resp = maker_client.patch(
            "/admin/_api/gov-orders/1/quick-edit",
            json={"field": "is_urgent", "value": "true"},
            headers={CSRF_HEADER_NAME: csrf_m, "Accept": "application/json"},
        )
        assert quick_resp.status_code == 403
        assert "four-eyes approval" in quick_resp.get_json()["error"]

        bulk_del_resp = maker_client.post(
            "/admin/gov-orders/action/delete",
            data={CSRF_FORM_FIELD: csrf_m, "selected_pks": ["1"]},
            follow_redirects=True,
        )
        assert bulk_del_resp.status_code == 200
        assert "require four-eyes approval" in bulk_del_resp.get_data(as_text=True)

        # 6. Edit queues, then reject leaves DB unchanged and records approval_rejected
        edit_page = maker_client.get("/admin/gov-orders/1/edit")
        csrf_e = extract_csrf(edit_page.get_data(as_text=True))
        edit_queue = maker_client.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf_e,
                "reference": "ORD-100",
                "status": "cancelled",
                "amount": "999.00",
                "version": "1",
            },
            follow_redirects=False,
        )
        assert edit_queue.status_code in {302, 303}
        edit_req = deck.approval_store.list_requests(status="pending")[0]
        assert edit_req.operation == "edit"

        rej_resp = checker_client.post(
            f"/admin/_approvals/{edit_req.id}/reject",
            data={CSRF_FORM_FIELD: csrf_c, "review_note": "Amount mismatch"},
            follow_redirects=False,
        )
        assert rej_resp.status_code in {302, 303}
        assert "approval.rejected" in events
        with SessionLocal() as s:
            o1 = s.get(GovOrder, 1)
            assert o1 is not None
            assert o1.status == "pending"

        # 7. Individual delete + @action(require_approval=True)
        act_resp = maker_client.post(
            "/admin/gov-orders/action/refund_orders",
            data={CSRF_FORM_FIELD: csrf_m, "selected_pks": ["1"]},
            follow_redirects=False,
        )
        assert act_resp.status_code in {302, 303}
        act_req = deck.approval_store.list_requests(status="pending")[0]
        assert act_req.operation == "action"
        checker_client.post(
            f"/admin/_approvals/{act_req.id}/approve",
            data={CSRF_FORM_FIELD: csrf_c},
            follow_redirects=False,
        )
        with SessionLocal() as s:
            o1 = s.get(GovOrder, 1)
            assert o1 is not None
            assert o1.status == "refunded"

        del_resp = maker_client.post(
            "/admin/gov-orders/1/delete",
            data={CSRF_FORM_FIELD: csrf_m},
            follow_redirects=False,
        )
        assert del_resp.status_code in {302, 303}
        del_req = deck.approval_store.list_requests(status="pending")[0]
        assert del_req.operation == "delete"
        assert del_req.diff["api_token"] == {"old": "[REDACTED]", "new": "[REDACTED]"}
        checker_client.post(
            f"/admin/_approvals/{del_req.id}/approve",
            data={CSRF_FORM_FIELD: csrf_c},
            follow_redirects=False,
        )
        with SessionLocal() as s:
            assert s.get(GovOrder, 1) is None
    finally:
        deck.close()
        eng.dispose()


def test_optimistic_concurrency_control_explicit_version_and_implicit_hash(
    tmp_path: Path,
) -> None:
    # A. Explicit version_column = "version"
    app, deck, eng, SessionLocal = _setup_sqlite_deck(
        tmp_path,
        approval_required=False,
        version_column="version",
    )
    try:
        c1 = app.test_client()
        c2 = app.test_client()
        login_as(c1, "admin", "admin-password")
        login_as(c2, "maker", "maker-password")

        page1 = c1.get("/admin/gov-orders/1/edit")
        page2 = c2.get("/admin/gov-orders/1/edit")
        _assert_strict_csp(page1)
        html1 = page1.get_data(as_text=True)
        html2 = page2.get_data(as_text=True)
        csrf1 = extract_csrf(html1)
        csrf2 = extract_csrf(html2)
        ver_match1 = re.search(r'name="_deck_version" value="([^"]*)"', html1)
        ver_match2 = re.search(r'name="_deck_version" value="([^"]*)"', html2)
        assert ver_match1 and ver_match2
        assert ver_match1.group(1) == "1"

        # User 1 saves first -> succeeds and bumps version to 2
        save1 = c1.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf1,
                "_deck_version": ver_match1.group(1),
                "reference": "ORD-100",
                "status": "approved",
                "amount": "275.00",
                "version": "1",
            },
            follow_redirects=False,
        )
        assert save1.status_code in {302, 303}
        with SessionLocal() as s:
            o1 = s.get(GovOrder, 1)
            assert o1 is not None and o1.version == 2

        # User 2 submits stale token -> 409 Conflict with 3-way diff
        conflict = c2.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf2,
                "_deck_version": ver_match2.group(1),
                "reference": "ORD-100",
                "status": "disputed",
                "amount": "310.00",
                "version": "1",
            },
        )
        assert conflict.status_code == 409
        conflict_html = conflict.get_data(as_text=True)
        assert "3-Way Concurrent Edit Conflict" in conflict_html
        assert "disputed" in conflict_html
        assert "approved" in conflict_html
        _assert_strict_csp(conflict)

        # Force overwrite with stale version overrides cleanly and bumps version to 3
        forced = c2.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf2,
                "_deck_version": ver_match2.group(1),
                "_deck_force_overwrite": "1",
                "reference": "ORD-100",
                "status": "disputed",
                "amount": "310.00",
                "version": "1",
            },
            follow_redirects=False,
        )
        assert forced.status_code in {302, 303}
        with SessionLocal() as s:
            o1 = s.get(GovOrder, 1)
            assert o1 is not None
            assert o1.version == 3
            assert o1.status == "disputed"
    finally:
        deck.close()
        eng.dispose()

    # B. Implicit content hash (version_column=None)
    sub_dir = tmp_path / "implicit_occ"
    sub_dir.mkdir(parents=True, exist_ok=True)
    app2, deck2, eng2, _ = _setup_sqlite_deck(
        sub_dir,
        approval_required=False,
        version_column=None,
    )
    try:
        c1 = app2.test_client()
        c2 = app2.test_client()
        login_as(c1, "admin", "admin-password")
        login_as(c2, "maker", "maker-password")

        h1 = c1.get("/admin/gov-orders/1/edit").get_data(as_text=True)
        h2 = c2.get("/admin/gov-orders/1/edit").get_data(as_text=True)
        v1 = re.search(r'name="_deck_version" value="([^"]+)"', h1).group(1)  # type: ignore[union-attr]
        v2 = re.search(r'name="_deck_version" value="([^"]+)"', h2).group(1)  # type: ignore[union-attr]
        assert len(v1) == 24  # SHA-256[:24] implicit token

        c1.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: extract_csrf(h1),
                "_deck_version": v1,
                "reference": "ORD-100",
                "status": "paid",
                "amount": "250.00",
                "version": "1",
            },
        )
        resp_409 = c2.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: extract_csrf(h2),
                "_deck_version": v2,
                "reference": "ORD-100",
                "status": "void",
                "amount": "250.00",
                "version": "1",
            },
        )
        assert resp_409.status_code == 409
    finally:
        deck2.close()
        eng2.dispose()


def test_audit_hash_chain_tamper_detection_date_filter_and_streaming_export(
    tmp_path: Path,
) -> None:
    app, deck, eng, _ = _setup_sqlite_deck(tmp_path, hash_chain=True, approval_required=False)
    try:
        assert isinstance(deck.audit_store, SQLAlchemyAuditStore)
        yesterday = datetime.now(timezone.utc) - timedelta(days=2)
        today = datetime.now(timezone.utc)

        deck.audit_store.record(
            AuditEntry(
                id="e-old",
                timestamp=yesterday,
                actor_id="u-adm",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="gov-orders",
                model_label="Gov Order",
                record_pk="1",
                record_repr="Order ORD-100",
                changes={"reference": {"old": "OLD", "new": "=CMD|' /C calc'!A0"}},
                metadata={"note": "older event"},
            )
        )
        deck.audit_store.record(
            AuditEntry(
                id="e-new",
                timestamp=today,
                actor_id="u-adm",
                actor_name="Admin",
                actor_ip="127.0.0.1",
                action="update",
                model_slug="gov-orders",
                model_label="Gov Order",
                record_pk="1",
                record_repr="Order ORD-100",
                changes={
                    "amount": {"old": "100.00", "new": "250.00"},
                    "api_token": {"old": "[REDACTED]", "new": "[REDACTED]"},
                },
                metadata={"note": "today event"},
            )
        )
        ok, err = deck.audit_store.verify_chain()
        assert ok is True and err is None

        adm_client = app.test_client()
        sup_client = app.test_client()
        login_as(adm_client, "admin", "admin-password")
        login_as(sup_client, "support", "support-password")

        # UI shows Hash-Chained Verified badge + date range filter works
        today_str = today.strftime("%Y-%m-%d")
        audit_page = adm_client.get(f"/admin/_audit?date_from={today_str}&date_to={today_str}")
        assert audit_page.status_code == 200
        audit_html = audit_page.get_data(as_text=True)
        assert "Hash-Chained · Verified" in audit_html
        assert "today event" in audit_html
        assert "older event" not in audit_html
        _assert_strict_csp(audit_page)

        # Export JSONL + CSV as support (masked amount / hidden api_token sanitized; CSV formula escaped)
        csv_resp = sup_client.get("/admin/_audit/export?format=csv")
        assert csv_resp.status_code == 200
        csv_text = csv_resp.get_data(as_text=True)
        rows = list(csv.reader(io.StringIO(csv_text)))
        assert len(rows) == 3  # header + 2 entries
        # Support has field restrictions -> changes redacted in sanitized export
        jsonl_resp = adm_client.get(f"/admin/_audit/export?format=jsonl&date_from={today_str}")
        assert jsonl_resp.status_code == 200
        jlines = [json.loads(line) for line in jsonl_resp.get_data(as_text=True).splitlines() if line]
        assert len(jlines) == 1
        assert jlines[0]["id"] == "e-new"

        csv_adm = adm_client.get("/admin/_audit/export?format=csv").get_data(as_text=True)
        assert "=CMD|" in csv_adm  # contained inside changes_json string

        # Direct SQL tamper triggers verify_chain() failure, CRITICAL diagnostic, and CLI exit 1
        with eng.begin() as conn:
            conn.execute(
                sa.text(
                    "UPDATE flask_deck_audit_logs SET record_repr = 'Tampered Order' WHERE id = 'e-old'"
                )
            )
        tamper_ok, tamper_msg = deck.audit_store.verify_chain()
        assert tamper_ok is False and tamper_msg is not None

        findings = run_security_audit(app, deck)
        assert any(
            f["severity"] == "CRITICAL" and f["category"] == "audit" for f in findings
        )

        runner = app.test_cli_runner()
        cli_res = runner.invoke(deck_cli, ["audit"])
        assert cli_res.exit_code == 1
        assert "CRITICAL" in cli_res.output
    finally:
        deck.close()
        eng.dispose()


def test_inline_and_csv_import_row_level_audit_history(tmp_path: Path) -> None:
    app, deck, eng, SessionLocal = _setup_sqlite_deck(
        tmp_path,
        approval_required=False,
        version_column=None,
        with_inline=True,
    )
    try:
        adm = app.test_client()
        login_as(adm, "admin", "admin-password")

        edit_page = adm.get("/admin/gov-orders/1/edit")
        csrf = extract_csrf(edit_page.get_data(as_text=True))

        # Add an inline child line item when editing GovOrder #1
        adm.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf,
                "reference": "ORD-100",
                "status": "pending",
                "amount": "250.00",
                "version": "1",
                "inline__gov-line-items__0__sku": "SKU-X1",
                "inline__gov-line-items__0__qty": "3",
            },
            follow_redirects=False,
        )

        with SessionLocal() as s:
            items = list(s.scalars(sa.select(GovLineItem).where(GovLineItem.order_id == 1)).all())
            assert len(items) == 1
            child_id = items[0].id

        # Edit inline row
        adm.post(
            "/admin/gov-orders/1/edit",
            data={
                CSRF_FORM_FIELD: csrf,
                "reference": "ORD-100",
                "status": "pending",
                "amount": "250.00",
                "version": "1",
                "inline__gov-line-items__0___pk": str(child_id),
                "inline__gov-line-items__0__sku": "SKU-X1",
                "inline__gov-line-items__0__qty": "5",
            },
            follow_redirects=False,
        )

        hist_html = adm.get("/admin/gov-orders/1/history").get_data(as_text=True)
        assert "inline_create" in hist_html
        assert "inline_edit" in hist_html
        assert deck.audit_store is not None
        inline_edits, _ = deck.audit_store.list_entries(model_slug="gov-orders", action="inline_edit")
        assert len(inline_edits) == 1
        assert inline_edits[0].changes["qty"] == {"old": 3, "new": 5}
        edit_rev_html = adm.get(f"/admin/gov-orders/1/history?rev={inline_edits[0].id}").get_data(as_text=True)
        assert "Qty" in edit_rev_html
        inline_creates, _ = deck.audit_store.list_entries(model_slug="gov-orders", action="inline_create")
        assert len(inline_creates) == 1
        assert inline_creates[0].changes["sku"]["new"] == "SKU-X1"
        create_rev_html = adm.get(f"/admin/gov-orders/1/history?rev={inline_creates[0].id}").get_data(as_text=True)
        assert "SKU-X1" in create_rev_html

        # CSV Import dry-run -> commit produces per-row audit entries on /<slug>/<pk>/history
        imp_page = adm.get("/admin/gov-orders/import")
        imp_csrf = extract_csrf(imp_page.get_data(as_text=True))
        csv_bytes = b"reference,status,amount\nORD-IMP-1,paid,120.00\n"
        preview_resp = adm.post(
            "/admin/gov-orders/import",
            data={
                CSRF_FORM_FIELD: imp_csrf,
                "step": "preview",
                "file": (io.BytesIO(csv_bytes), "orders.csv"),
            },
            content_type="multipart/form-data",
        )
        assert preview_resp.status_code == 200
        preview_token = re.search(
            r'name="preview_token" value="([^"]+)"', preview_resp.get_data(as_text=True)
        ).group(1)  # type: ignore[union-attr]

        commit_resp = adm.post(
            "/admin/gov-orders/import",
            data={
                CSRF_FORM_FIELD: imp_csrf,
                "step": "commit",
                "preview_token": preview_token,
            },
            follow_redirects=False,
        )
        assert commit_resp.status_code in {302, 303}

        with SessionLocal() as s:
            imp_ord = s.scalar(sa.select(GovOrder).where(GovOrder.reference == "ORD-IMP-1"))
            assert imp_ord is not None
            imp_pk = imp_ord.id

        imp_entries, _ = deck.audit_store.list_entries(model_slug="gov-orders", record_pk=str(imp_pk))
        assert len(imp_entries) == 1
        assert imp_entries[0].action == "create"
        assert imp_entries[0].metadata["source"] == "import"
        imp_hist = adm.get(f"/admin/gov-orders/{imp_pk}/history").get_data(as_text=True)
        assert "ORD-IMP-1" in imp_hist
    finally:
        deck.close()
        eng.dispose()


def test_saved_views_rbac_role_default_and_record_notes_xss_pinning(
    tmp_path: Path,
) -> None:
    app, deck, eng, SessionLocal = _setup_sqlite_deck(
        tmp_path, approval_required=False, version_column=None
    )
    with SessionLocal() as s:
        s.add(
            GovOrder(
                reference="ORD-SHIPPED",
                status="shipped",
                amount=Decimal("55.00"),
                version=1,
            )
        )
        s.commit()

    try:
        adm = app.test_client()
        sup = app.test_client()
        maker = app.test_client()
        login_as(adm, "admin", "admin-password")
        login_as(sup, "support", "support-password")
        login_as(maker, "maker", "maker-password")

        sup_list = sup.get("/admin/gov-orders/")
        sup_csrf = extract_csrf(sup_list.get_data(as_text=True))

        # Support can save personal view, CANNOT create team or role default views (403)
        sv_pers = sup.post(
            "/admin/_api/gov-orders/saved-views",
            json={"name": "My Pending", "query_string": "f_status=pending", "scope": "personal"},
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert sv_pers.status_code == 201

        sv_team_deny = sup.post(
            "/admin/_api/gov-orders/saved-views",
            json={"name": "Team View", "query_string": "f_status=pending", "scope": "team"},
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert sv_team_deny.status_code == 403

        # Admin creates role-default saved view for 'support'
        adm_csrf = extract_csrf(adm.get("/admin/gov-orders/").get_data(as_text=True))
        sv_role = adm.post(
            "/admin/_api/gov-orders/saved-views",
            json={
                "name": "Support Triage Queue",
                "query_string": "f_status=pending",
                "scope": "role",
                "default_for_role": "support",
            },
            headers={CSRF_HEADER_NAME: adm_csrf, "Accept": "application/json"},
        )
        assert sv_role.status_code == 201
        role_view_id = sv_role.get_json()["saved_view"]["id"]

        # Bare list URL for support auto-applies 'f_status=pending' (shows ORD-100, omits ORD-SHIPPED)
        sup_default_page = sup.get("/admin/gov-orders/")
        assert sup_default_page.status_code == 200
        def_html = sup_default_page.get_data(as_text=True)
        assert "Showing role default view" in def_html
        assert "ORD-100" in def_html
        assert "ORD-SHIPPED" not in def_html
        _assert_strict_csp(sup_default_page)

        # Support cannot delete admin's role view (403)
        del_forbidden = sup.post(
            f"/admin/_api/gov-orders/saved-views/{role_view_id}/delete",
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert del_forbidden.status_code == 403

        # Record notes: safe markdown, XSS sanitization, pinning order, RBAC & audit
        # Test markdown helper directly for javascript: and script tag safety
        rendered_xss = str(
            render_safe_markdown(
                "<script>alert(1)</script> **Watch** [bad](javascript:alert(1)) [ok](https://example.com)"
            )
        )
        assert "<script>" not in rendered_xss
        assert "href=\"javascript:" not in rendered_xss
        assert "<strong>Watch</strong>" in rendered_xss
        assert 'href="https://example.com"' in rendered_xss

        # Add unpinned normal note as support, then pinned warning note
        n1 = sup.post(
            "/admin/_api/gov-orders/1/notes",
            json={"body": "First note <script>evil()</script>", "pinned": False},
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert n1.status_code == 201
        n1_id = n1.get_json()["note"]["id"]

        n2 = sup.post(
            "/admin/_api/gov-orders/1/notes",
            json={"body": "**VIP Account** Hold before refund", "pinned": True},
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert n2.status_code == 201

        detail_resp = sup.get("/admin/gov-orders/1")
        assert detail_resp.status_code == 200
        detail_html = detail_resp.get_data(as_text=True)
        assert "<script>evil()" not in detail_html
        assert "&lt;script&gt;evil()&lt;/script&gt;" in detail_html
        assert detail_html.index("VIP Account") < detail_html.index("First note")
        _assert_strict_csp(detail_resp)

        drawer_resp = sup.get("/admin/_api/gov-orders/1/drawer")
        assert drawer_resp.status_code == 200
        assert "VIP Account" in drawer_resp.get_data(as_text=True)

        # Non-author non-superuser ('maker') cannot delete support's note (403)
        maker_csrf = extract_csrf(maker.get("/admin/gov-orders/1").get_data(as_text=True))
        del_note_deny = maker.post(
            f"/admin/_api/gov-orders/1/notes/{n1_id}/delete",
            headers={CSRF_HEADER_NAME: maker_csrf, "Accept": "application/json"},
        )
        assert del_note_deny.status_code == 403

        # Author deletes own note cleanly
        del_note_ok = sup.post(
            f"/admin/_api/gov-orders/1/notes/{n1_id}/delete",
            headers={CSRF_HEADER_NAME: sup_csrf, "Accept": "application/json"},
        )
        assert del_note_ok.status_code == 200

        # Audit entries exist for note_added / note_deleted
        assert deck.audit_store is not None
        note_audits, _ = deck.audit_store.list_entries(model_slug="gov-orders", action="note_added")
        assert len(note_audits) == 2
        del_audits, _ = deck.audit_store.list_entries(model_slug="gov-orders", action="note_deleted")
        assert len(del_audits) == 1
    finally:
        deck.close()
        eng.dispose()


def test_in_memory_m3_stores_parity() -> None:
    app_store = InMemoryApprovalStore()
    req = make_approval_request(
        model_slug="gov-orders",
        model_label="Gov Order",
        operation="edit",
        record_pk="1",
        record_repr="Order #1",
        payload={},
        diff={"status": {"old": "pending", "new": "paid"}},
        reason="check",
        requester_id="u-1",
        requester_name="Alice",
    )
    created = app_store.create(req)
    assert app_store.pending_count() == 1
    assert app_store.resolve(created.id, status="approved", reviewer_id="u-1", reviewer_name="Alice") is None
    resolved = app_store.resolve(created.id, status="approved", reviewer_id="u-2", reviewer_name="Bob")
    assert resolved is not None and resolved.status == "approved"
    assert app_store.pending_count() == 0

    aud_store = InMemoryAuditStore(hash_chain=True)
    aud_store.record(
        AuditEntry(
            id="mem-1",
            timestamp=datetime.now(timezone.utc),
            actor_id="u-1",
            actor_name="Alice",
            actor_ip="127.0.0.1",
            action="create",
            model_slug="gov-orders",
            model_label="Gov Order",
            record_pk="1",
            record_repr="Order #1",
        )
    )
    ok, err = aud_store.verify_chain()
    assert ok is True and err is None

    sv_store = InMemorySavedViewStore()
    sv = sv_store.create(
        SavedViewRecord(
            id="",
            model_slug="gov-orders",
            name="Default Pending",
            query_string="f_status=pending",
            scope="role",
            owner_id="u-1",
            owner_name="Alice",
            default_for_role="support",
        )
    )
    assert len(sv_store.list_for_model("gov-orders", user_id="u-2", roles=("support",))) == 1
    assert sv_store.delete(sv.id, actor_id="u-2", is_superuser=False) is False
    assert sv_store.delete(sv.id, actor_id="u-1", is_superuser=False) is True

    note_store = InMemoryRecordNoteStore()
    n = note_store.add(
        RecordNote(
            id="",
            model_slug="gov-orders",
            record_pk="1",
            author_id="u-1",
            author_name="Alice",
            body="Check invoice",
        )
    )
    toggled = note_store.toggle_pin(n.id, model_slug="gov-orders", record_pk="1")
    assert toggled is not None and toggled.pinned is True
    assert note_store.delete(n.id, actor_id="u-1") is True
