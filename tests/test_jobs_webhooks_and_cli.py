"""Behavioral tests for background jobs, SSE/artifact ACLs, webhooks DLQ, and Flask CLI."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from flask_deck import (
    Deck,
    DeckUser,
    InMemoryWebhookDeliveryStore,
    JobContext,
    ModelView,
    RBACAuthProvider,
    Role,
    SQLAlchemyAuthProvider,
    SQLAlchemyJobBackend,
    ThreadPoolJobBackend,
    WebhookSink,
)
from flask_deck.cli import deck_cli
from flask_deck.cli import main as cli_main
from flask_deck.events import DeckEvent
from flask_deck.security import CSRF_FORM_FIELD
from tests._backends import sqlite_memory_engine


class JobBase(DeclarativeBase):
    pass


class JobWidget(JobBase):
    __tablename__ = "job_widgets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)


class JobWidgetViewA(ModelView):
    model = JobWidget
    slug = "widgets-a"


class JobWidgetViewB(ModelView):
    model = JobWidget
    slug = "widgets-b"


def _wait_terminal(backend: Any, job_id: str, timeout: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rec = backend.get(job_id)
        if rec is not None and rec.status in {"succeeded", "failed", "cancelled"}:
            return rec
        time.sleep(0.02)
    raise AssertionError(f"Job {job_id} did not finish")


def test_job_backends_cancellation_eviction_logs_and_resolver(tmp_path: Path) -> None:
    # 1. ThreadPoolJobBackend: eviction callback (incl. error resilience), log cap, queued + running cancel, non-str return
    evicted_ids: list[str] = []

    def _on_evict(rec: Any) -> None:
        evicted_ids.append(rec.id)
        if len(evicted_ids) == 1:
            raise RuntimeError("cleanup boom")

    tp = ThreadPoolJobBackend(max_workers=1, max_history=10, max_logs_per_job=10)
    tp.set_on_evict(_on_evict)
    try:
        # Exceed max_history to trigger eviction
        for idx in range(12):
            rec = tp.submit(
                name=f"j{idx}",
                label=f"Job {idx}",
                actor_id="u1",
                actor_name="U1",
                model_slug="",
                fn=lambda ctx, i=idx: _log_many(ctx, i),  # type: ignore[misc]
                on_complete=lambda _r: (_ for _ in ()).throw(RuntimeError("cb err")),
            )
            _wait_terminal(tp, rec.id)
        assert len(evicted_ids) >= 2
        latest = tp.list_jobs(actor_id="u1", limit=1)[0]
        assert len(latest.logs) == 10  # capped at max_logs_per_job
        assert latest.to_dict()["duration_ms"] is not None

        # Cooperative cancel on both running AND queued jobs (max_workers=1 holds slot)
        started = threading.Event()
        release = threading.Event()

        def _blocker(ctx: JobContext) -> str:
            started.set()
            release.wait(timeout=3.0)
            return "done"

        j_run = tp.submit(name="run", label="Running", actor_id="u1", actor_name="U1", model_slug="", fn=_blocker)
        assert started.wait(timeout=3.0)
        j_q = tp.submit(name="queued", label="Queued", actor_id="u1", actor_name="U1", model_slug="", fn=lambda _c: "never")
        assert tp.cancel(j_q.id) is True
        assert tp.cancel(j_run.id) is True
        assert tp.cancel("missing") is False
        release.set()
        assert _wait_terminal(tp, j_run.id).status == "cancelled"
        assert _wait_terminal(tp, j_q.id).status == "cancelled"
        assert tp.retry("missing") is None
    finally:
        tp.shutdown(wait=True)

    # 2. SQLAlchemyJobBackend with db_uri + callable_resolver + cooperative cancel + log cap
    with pytest.raises(ValueError, match="Provide engine or db_uri"):
        SQLAlchemyJobBackend()

    sa_db = f"sqlite:///{tmp_path / 'jobs.db'}"
    sb = SQLAlchemyJobBackend(db_uri=sa_db, max_workers=1, max_logs_per_job=10)
    try:
        j_fail = sb.submit(
            name="resolvable",
            label="Fail Once",
            actor_id="u1",
            actor_name="U1",
            model_slug="",
            fn=lambda ctx: _log_and_fail(ctx),
        )
        fin = _wait_terminal(sb, j_fail.id)
        assert fin.status == "failed" and len(fin.logs) == 10

        # Simulate process restart: clear in-memory _callables, resolve via callable_resolver
        sb._callables.clear()
        assert sb.can_retry(j_fail.id) is False
        assert sb.retry(j_fail.id) is None

        sb.set_callable_resolver(lambda name: (lambda _c: "recovered") if name == "resolvable" else None)
        assert sb.can_retry(j_fail.id) is True
        retried = sb.retry(j_fail.id, actor_id="u2", actor_name="U2")
        assert retried is not None
        assert _wait_terminal(sb, retried.id).status == "succeeded"

        # Running + queued cancel on SQLAlchemyJobBackend
        s2 = threading.Event()
        r2 = threading.Event()

        def _blk2(ctx: JobContext) -> str:
            s2.set()
            r2.wait(timeout=3.0)
            return "ok"

        jr2 = sb.submit(name="blk", label="Blk", actor_id="u1", actor_name="U1", model_slug="", fn=_blk2)
        assert s2.wait(timeout=3.0)
        jq2 = sb.submit(name="q2", label="Q2", actor_id="u1", actor_name="U1", model_slug="", fn=lambda _c: "x")
        assert sb.cancel(jq2.id) is True
        assert sb.cancel(jr2.id) is True
        assert sb.cancel("nonexistent") is False
        r2.set()
        assert _wait_terminal(sb, jr2.id).status == "cancelled"
        assert _wait_terminal(sb, jq2.id).status == "cancelled"
    finally:
        sb.shutdown(wait=True)


def _log_many(ctx: JobContext, idx: int) -> Any:
    for n in range(12):
        ctx.log(f"line-{n}")
    return {"ok": idx} if idx % 2 == 0 else None


def _log_and_fail(ctx: JobContext) -> str:
    for n in range(12):
        ctx.log(f"step-{n}")
    raise RuntimeError("boom")


def _login_and_csrf(client: Any, username: str, password: str) -> str:
    r_get = client.get("/admin/login")
    html = r_get.get_data(as_text=True)
    marker = 'name="_csrf_token" value="'
    tok = html.split(marker, 1)[1].split('"', 1)[0]
    r_post = client.post(
        "/admin/login",
        data={"username": username, "password": password, CSRF_FORM_FIELD: tok},
        follow_redirects=True,
    )
    assert r_post.status_code == 200
    body = r_post.get_data(as_text=True)
    meta_marker = 'name="deck-csrf" content="'
    return body.split(meta_marker, 1)[1].split('"', 1)[0]


def test_job_and_webhook_routes_sse_artifacts_and_acls() -> None:
    with sqlite_memory_engine() as eng:
        JobBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "job-routes-secret-32-bytes-long!"
        app.config["TESTING"] = True

        auth = RBACAuthProvider(
            roles=[
                Role("superadmin", permissions=frozenset({"*"})),
                Role("staff", permissions=frozenset({"widgets-a:view"})),
            ],
            accounts=[
                RBACAuthProvider.make_account(
                    user=DeckUser(id="admin", username="admin", roles=("superadmin",), is_superuser=True),
                    password="pass1234",
                ),
                RBACAuthProvider.make_account(
                    user=DeckUser(id="staff", username="staff", roles=("staff",)),
                    password="pass1234",
                ),
            ],
        )
        wh_store = InMemoryWebhookDeliveryStore()
        fail_mode = {"fail": False}

        def _fake_wh_transport(url: str, body: bytes, headers: dict[str, str], timeout: float) -> int:
            _ = (url, body, headers, timeout)
            return 503 if fail_mode["fail"] else 200

        sink = WebhookSink(
            "https://hooks.acme.internal/test",
            secret="wh-secret-32-chars-minimum-ok!!",
            async_delivery=False,
            max_retries=1,
            retry_delays=(0.0,),
            delivery_store=wh_store,
            transport=_fake_wh_transport,
        )
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng,
            auth=auth,
            enable_webhooks_ui=True,
        )
        deck.webhook_delivery_store = wh_store
        deck.add_webhook(sink)
        deck.register(JobWidgetViewA)

        @deck.scheduled_job("nightly_check", label="Nightly Check", schedule="0 3 * * *")
        def _nightly(ctx: JobContext) -> str:
            ctx.log("running nightly")
            deck.job_storage.save(b"col\n1\n", key="jobs/report.csv", content_type="text/csv")
            ctx.attach_artifact(key="jobs/report.csv", filename="report.csv", content_type="text/csv")
            return "Nightly ok"

        try:
            admin_c = app.test_client()
            csrf_a = _login_and_csrf(admin_c, "admin", "pass1234")
            staff_c = app.test_client()
            csrf_s = _login_and_csrf(staff_c, "staff", "pass1234")

            # Trigger scheduled job: staff unauthorized 403, unknown 404, admin succeeds
            assert staff_c.post("/admin/_jobs/scheduled/nightly_check/run", data={CSRF_FORM_FIELD: csrf_s}).status_code == 403
            assert admin_c.post("/admin/_jobs/scheduled/missing/run", data={CSRF_FORM_FIELD: csrf_a}).status_code == 404
            r_sched = admin_c.post("/admin/_jobs/scheduled/nightly_check/run", data={CSRF_FORM_FIELD: csrf_a}, follow_redirects=False)
            assert r_sched.status_code == 302

            assert deck.job_backend is not None
            job = deck.job_backend.list_jobs(limit=1)[0]
            _wait_terminal(deck.job_backend, job.id)

            # JSON status, SSE stream, anti-enumeration 403 for non-owner vs 404 for superuser
            assert admin_c.get(f"/admin/_api/jobs/{job.id}").status_code == 200
            assert admin_c.get("/admin/_api/jobs/nonexistent").status_code == 404
            assert staff_c.get(f"/admin/_api/jobs/{job.id}").status_code == 403
            assert staff_c.get("/admin/_api/jobs/nonexistent").status_code == 403

            r_sse = admin_c.get(
                f"/admin/_api/jobs/{job.id}/stream?max_seconds=bad",
                headers={"Last-Event-ID": "bad"},
            )
            assert r_sse.status_code == 200 and b"data:" in r_sse.data
            assert admin_c.get("/admin/_api/jobs/nonexistent/stream").status_code == 404

            # Cancel & retry already-succeeded job
            assert admin_c.post(f"/admin/_jobs/{job.id}/cancel", data={CSRF_FORM_FIELD: csrf_a}).status_code == 302
            assert admin_c.post(f"/admin/_jobs/{job.id}/retry", data={CSRF_FORM_FIELD: csrf_a}).status_code == 302

            # Artifact download: staff 403, admin 200 with sandbox CSP, deleted storage file -> 404
            assert staff_c.get(f"/admin/_jobs/{job.id}/artifact").status_code == 403
            r_art = admin_c.get(f"/admin/_jobs/{job.id}/artifact")
            assert r_art.status_code == 200 and r_art.data == b"col\n1\n"
            assert "sandbox" in r_art.headers["Content-Security-Policy"]
            deck.job_storage.delete("jobs/report.csv")
            assert admin_c.get(f"/admin/_jobs/{job.id}/artifact").status_code == 404

            # Webhooks UI, test dispatch, and redelivery (success + failure + missing + unauthorized)
            assert staff_c.get("/admin/_webhooks").status_code == 403
            assert admin_c.get("/admin/_webhooks").status_code == 200
            assert admin_c.post("/admin/_webhooks/test", data={CSRF_FORM_FIELD: csrf_a, "sink_index": "99"}).status_code == 404
            assert admin_c.post("/admin/_webhooks/test", data={CSRF_FORM_FIELD: csrf_a, "sink_index": "bad"}).status_code == 302

            fail_mode["fail"] = True
            sink(DeckEvent(name="test.fail", actor_id="admin", actor_name="Admin"))
            dlq = wh_store.list_deliveries(status="dead_letter")[0]
            assert admin_c.post("/admin/_webhooks/missing/redeliver", data={CSRF_FORM_FIELD: csrf_a}).status_code == 404
            assert admin_c.post(f"/admin/_webhooks/{dlq.id}/redeliver", data={CSRF_FORM_FIELD: csrf_a}).status_code == 302
            fail_mode["fail"] = False
            assert admin_c.post(f"/admin/_webhooks/{dlq.id}/redeliver", data={CSRF_FORM_FIELD: csrf_a}).status_code == 302
        finally:
            deck.close()


def test_cli_commands_and_error_paths(tmp_path: Path) -> None:
    # 1. App without Deck registered
    bare_app = Flask("bare")
    bare_app.cli.add_command(deck_cli)
    bare_runner = bare_app.test_cli_runner()
    assert bare_runner.invoke(args=["deck", "info"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "audit", "--format", "json"]).exit_code == 0
    assert bare_runner.invoke(args=["deck", "audit", "--format", "sarif"]).exit_code == 0
    assert bare_runner.invoke(args=["deck", "scaffold"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "jobs", "list"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "jobs", "run", "x"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "createsuperuser", "--no-input"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "changepassword", "u"]).exit_code == 1
    assert bare_runner.invoke(args=["deck", "mcp"]).exit_code == 1

    # 2. Full app with SQLAlchemyAuthProvider, duplicate model class scaffold, jobs, IAM CLI
    with sqlite_memory_engine() as eng:
        JobBase.metadata.create_all(eng)
        SessionLocal = sessionmaker(bind=eng, autoflush=False, expire_on_commit=False)
        app = Flask("cli_app")
        app.config["SECRET_KEY"] = "cli-test-secret-32-bytes-long!!"
        app.cli.add_command(deck_cli)
        auth = SQLAlchemyAuthProvider(eng, password_min_length=8)
        deck = Deck(app, session_factory=SessionLocal, engine=eng, auth=auth, environment="development")
        deck.register(JobWidgetViewA, JobWidgetViewB)

        @deck.scheduled_job("ok_job", label="OK Job", schedule="@hourly")
        def _ok_job(ctx: JobContext) -> str:
            return "all good"

        @deck.scheduled_job("bad_job", label="Bad Job", schedule="@daily")
        def _bad_job(ctx: JobContext) -> str:
            raise RuntimeError("broken")

        runner = app.test_cli_runner()
        try:
            assert runner.invoke(args=["deck", "info"]).exit_code == 0
            assert runner.invoke(args=["deck", "audit", "--format", "sarif"]).exit_code == 0

            out_file = tmp_path / "views.py"
            r_scaf = runner.invoke(args=["deck", "scaffold", "--output", str(out_file)])
            assert r_scaf.exit_code == 0
            scaf_text = out_file.read_text(encoding="utf-8")
            assert "class JobWidgetView(" in scaf_text and "class WidgetsBView(" in scaf_text

            assert runner.invoke(args=["deck", "jobs", "list"]).exit_code == 0
            assert runner.invoke(args=["deck", "jobs", "run", "ok_job"]).exit_code == 0
            assert runner.invoke(args=["deck", "jobs", "run", "bad_job"]).exit_code == 1
            assert runner.invoke(args=["deck", "jobs", "run", "missing"]).exit_code == 1

            # createsuperuser & changepassword edge cases + happy paths
            assert runner.invoke(args=["deck", "createsuperuser", "--deck-name", "missing"]).exit_code == 1
            assert runner.invoke(args=["deck", "createsuperuser", "--no-input"]).exit_code == 1
            assert runner.invoke(args=["deck", "createsuperuser", "--no-input", "--username", "root"]).exit_code == 1
            assert (
                runner.invoke(
                    args=["deck", "createsuperuser", "--no-input", "--username", "root", "--password", "short"]
                ).exit_code
                == 1
            )
            assert (
                runner.invoke(
                    args=["deck", "createsuperuser", "--username", "root", "--email", "r@a.dev", "--password", "StrongPass123!"]
                ).exit_code
                == 0
            )
            assert (
                runner.invoke(
                    args=["deck", "changepassword", "missing", "--password", "NewPass123!"]
                ).exit_code
                == 1
            )
            assert (
                runner.invoke(
                    args=["deck", "changepassword", "root", "--password", "short"]
                ).exit_code
                == 1
            )
            assert (
                runner.invoke(
                    args=["deck", "changepassword", "root", "--password", "RotatedPass456!"]
                ).exit_code
                == 0
            )
            assert runner.invoke(args=["deck", "changepassword", "root", "--deck-name", "missing"]).exit_code == 1
            assert runner.invoke(args=["deck", "mcp", "--deck-name", "missing"]).exit_code == 1
        finally:
            deck.close()

    # Standalone entry point
    assert cli_main(["version"]) == 0
    assert cli_main([]) == 0


def test_rate_limiter_lockout_jobs_cancel_sse_nan_webhooks_and_redis_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import http.client

    import flask_deck.events as events_mod
    import flask_deck.security as sec_mod
    from flask_deck.importer import RedisPreviewStore
    from flask_deck.security import RedisRateLimitStore, SQLAlchemyRateLimitStore

    # 1. SQLAlchemyRateLimitStore preserves active lockout even when window_seconds < lockout_seconds
    now_box = [1_700_000_000.0]
    monkeypatch.setattr(sec_mod.time, "time", lambda: now_box[0])
    with sqlite_memory_engine() as eng_rl:
        rl = SQLAlchemyRateLimitStore(eng_rl, max_attempts=2, window_seconds=10, lockout_seconds=60)
        rl.record_failure("10.0.0.1", "alice")
        assert rl.is_locked("10.0.0.1", "alice") == (False, 0)
        rl.record_failure("10.0.0.1", "alice")
        locked_1, retry_1 = rl.is_locked("10.0.0.1", "alice")
        assert locked_1 is True and retry_1 >= 59
        # Advance past window_seconds (15s > 10s), still inside 60s lockout
        now_box[0] += 15.0
        rl.record_failure("10.0.0.1", "alice")
        locked_2, retry_2 = rl.is_locked("10.0.0.1", "alice")
        assert locked_2 is True and retry_2 >= 40

    # 2. SQLAlchemyJobBackend supports sqlite:///:memory: (StaticPool) & cross-worker cancel()
    mem_jb = SQLAlchemyJobBackend(db_uri="sqlite:///:memory:", max_workers=1)
    try:
        j_mem = mem_jb.submit(
            name="mem_ok",
            label="In-memory SQLite job",
            actor_id="u1",
            actor_name="U1",
            model_slug="",
            fn=lambda _ctx: "mem-done",
        )
        res_mem = _wait_terminal(mem_jb, j_mem.id)
        assert res_mem.status == "succeeded" and res_mem.message == "mem-done"
    finally:
        mem_jb.shutdown(wait=True)

    shared_uri = f"sqlite:///{tmp_path / 'shared_cancel.db'}"
    w1 = SQLAlchemyJobBackend(db_uri=shared_uri, max_workers=1)
    w2 = SQLAlchemyJobBackend(db_uri=shared_uri, max_workers=1)
    started = threading.Event()
    observed_cancel = threading.Event()
    try:
        def _coop(ctx: JobContext) -> str:
            started.set()
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                if ctx.is_cancelled():
                    observed_cancel.set()
                    return "aborted"
                time.sleep(0.01)
            return "timed-out"

        j_shared = w1.submit(
            name="coop",
            label="Cross-worker cancel",
            actor_id="u1",
            actor_name="U1",
            model_slug="",
            fn=_coop,
        )
        assert started.wait(timeout=3.0)
        assert w2.cancel(j_shared.id) is True
        assert observed_cancel.wait(timeout=3.0)
        final_j = _wait_terminal(w1, j_shared.id)
        assert final_j.status == "cancelled"
    finally:
        w1.shutdown(wait=True)
        w2.shutdown(wait=True)

    # 3. SSE /_jobs/<id>/stream rejects NaN/Inf max_seconds cleanly without 500
    with sqlite_memory_engine() as eng_sse:
        JobBase.metadata.create_all(eng_sse)
        SessionLocal = sessionmaker(bind=eng_sse, autoflush=False, expire_on_commit=False)
        app = Flask(__name__)
        app.config["SECRET_KEY"] = "sse-nan-secret-32-bytes-long!!!!"
        app.config["TESTING"] = True
        jb_sse = ThreadPoolJobBackend(max_workers=1)
        deck = Deck(
            app,
            session_factory=SessionLocal,
            engine=eng_sse,
            allow_insecure_open=True,
            job_backend=jb_sse,
            audit_store=False,
        )
        try:
            j_done = jb_sse.submit(
                name="quick",
                label="Quick",
                actor_id="anonymous",
                actor_name="Anonymous",
                model_slug="",
                fn=lambda _c: "ok",
            )
            _wait_terminal(jb_sse, j_done.id)
            client = app.test_client()
            assert client.get(f"/admin/_api/jobs/{j_done.id}/stream?max_seconds=nan").status_code == 200
            assert client.get(f"/admin/_api/jobs/{j_done.id}/stream?max_seconds=inf").status_code == 200
        finally:
            deck.close()

    # 4. WebhookSink.send_test() bypasses event filter & IPv6 Host header is RFC 9110 bracketed
    sent_events: list[str] = []
    sink = WebhookSink(
        "https://hooks.example.test/events",
        secret="super-secret-webhook-signing-key",
        events=("record.created",),
        allow_private_ips=True,
        transport=lambda _url, _body, hdrs, _to: (sent_events.append(hdrs["X-Deck-Event"]) or 200),
    )
    sink(DeckEvent(name="webhook.test", payload={"ping": True}))
    assert sent_events == []  # filtered out by normal dispatch
    sink.send_test(DeckEvent(name="webhook.test", payload={"ping": True}))
    assert sent_events == ["webhook.test"]

    captured_host_hdrs: list[str] = []

    class _FakeResp:
        status = 200

        def read(self, _n: int = -1) -> bytes:
            return b"ok"

    class _FakeHTTPConn:
        def __init__(self, host: str, port: int = 80, timeout: float = 5.0) -> None:
            _ = (host, port, timeout)

        def request(self, _method: str, _path: str, *, body: bytes, headers: dict[str, str]) -> None:
            _ = body
            captured_host_hdrs.append(headers["Host"])

        def getresponse(self) -> _FakeResp:
            return _FakeResp()

        def close(self) -> None:
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", _FakeHTTPConn)
    status = events_mod._send_pinned_request(
        "http://[2606:4700:4700::1111]:8443/hook",
        pinned_ip="2606:4700:4700::1111",
        body=b"{}",
        headers={"Content-Type": "application/json"},
        timeout=2.0,
    )
    assert status == 200
    assert captured_host_hdrs == ["[2606:4700:4700::1111]:8443"]

    # 5. RedisPreviewStore & RedisRateLimitStore close() only closes owned clients
    class _FakeRedis:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    ext_client = _FakeRedis()
    p_ext = RedisPreviewStore(ext_client)
    r_ext = RedisRateLimitStore(ext_client)
    p_ext.close()
    r_ext.close()
    assert ext_client.closed is False

    owned_p = _FakeRedis()
    p_own = RedisPreviewStore(owned_p)
    p_own._owns_client = True
    p_own.close()
    assert owned_p.closed is True

    owned_r = _FakeRedis()
    r_own = RedisRateLimitStore(owned_r)
    r_own._owns_client = True
    r_own.close()
    assert owned_r.closed is True
