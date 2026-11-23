from __future__ import annotations

import gzip
import io
import statistics
import time
import tracemalloc
from decimal import Decimal
from pathlib import Path

import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import Deck, ModelView, QuickTab
from flask_deck.importer import run_dry_run_import


class BenchBase(DeclarativeBase):
    pass


class BenchOrg(BenchBase):
    __tablename__ = "bench_orgs"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False, index=True)

    def __str__(self) -> str:
        return self.name


class BenchOrder(BenchBase):
    __tablename__ = "bench_orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(sa.String(32), unique=True, index=True, nullable=False)
    status: Mapped[str] = mapped_column(sa.String(16), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(sa.Numeric(10, 2), nullable=False)
    notes: Mapped[str] = mapped_column(sa.Text, default="")
    org_id: Mapped[int] = mapped_column(sa.ForeignKey("bench_orgs.id"), index=True)
    org: Mapped[BenchOrg] = relationship()


class BenchOrderView(ModelView):
    model = BenchOrder
    columns = ("code", "org", "status", "amount")
    searchable_columns = ("code",)
    filterable_columns = ("status", "org_id")
    import_key_columns = ("code",)
    quick_tabs = (
        QuickTab("all", "All"),
        QuickTab("paid", "Paid", filters={"status": "paid"}),
        QuickTab("pending", "Pending", filters={"status": "pending"}),
        QuickTab("refunded", "Refunded", filters={"status": "refunded"}),
    )


def main() -> None:
    # 1. Dual Asset Budget Check (Core Shell < 18 KB gz, Max Route Page < 24 KB gz)
    pkg_static = Path(__file__).resolve().parents[1] / "src" / "flask_deck" / "static"
    css_gz = len(gzip.compress((pkg_static / "css" / "deck.css").read_bytes(), 9))
    core_js_gz = len(gzip.compress((pkg_static / "js" / "deck.js").read_bytes(), 9))
    core_kb = (css_gz + core_js_gz) / 1024.0
    print(
        f"[Assets Core] CSS: {css_gz / 1024:.2f} KB gz | Core JS: {core_js_gz / 1024:.2f} KB gz "
        f"| Core Total: {core_kb:.2f} KB gz"
    )
    assert core_kb < 18.0, f"Core asset budget exceeded: {core_kb:.2f} KB gz"
    for route_mod in ("deck-grid.js", "deck-form.js", "deck-ops.js"):
        mod_path = pkg_static / "js" / route_mod
        if mod_path.is_file():
            mod_gz = len(gzip.compress(mod_path.read_bytes(), 9))
            page_kb = (css_gz + core_js_gz + mod_gz) / 1024.0
            print(f"[Assets Route] +{route_mod}: {mod_gz / 1024:.2f} KB gz -> Page Total: {page_kb:.2f} KB gz")
            assert page_kb < 24.0, f"Route page budget exceeded for {route_mod}: {page_kb:.2f} KB gz"

    # 2. Seed 2,000 rows
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    BenchBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    statuses = ("paid", "pending", "refunded")
    with SessionLocal() as sess:
        orgs = [BenchOrg(name=f"Org-{i}") for i in range(25)]
        sess.add_all(orgs)
        sess.flush()
        sess.add_all(
            [
                BenchOrder(
                    code=f"ORD-{i:05d}",
                    status=statuses[i % 3],
                    amount=Decimal("49.90") + (i % 100),
                    notes="blob " * 80,
                    org_id=orgs[i % len(orgs)].id,
                )
                for i in range(2000)
            ]
        )
        sess.commit()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "benchmark-secret-key-thirty-two-bytes!!"
    app.config["TESTING"] = True
    deck = Deck(
        app,
        session_factory=SessionLocal,
        engine=engine,
        allow_insecure_open=True,
        auto_audit=False,
    )
    deck.register(BenchOrg, BenchOrderView)

    client = app.test_client()
    # Warm up
    assert client.get("/admin/bench-orders/?page_size=50").status_code == 200

    # 3. Measure List View Latency + Query Count (50 rows + FK + 4 QuickTabs)
    q_counts: list[int] = []
    latencies_ms: list[float] = []
    for _ in range(15):
        seen: list[str] = []

        def _count(_c: object, _cur: object, stmt: str, *_a: object, _buf: list[str] = seen) -> None:
            _buf.append(stmt)

        sa.event.listen(engine, "before_cursor_execute", _count)
        t0 = time.perf_counter()
        resp = client.get("/admin/bench-orders/?page_size=50")
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        sa.event.remove(engine, "before_cursor_execute", _count)
        assert resp.status_code == 200
        q_counts.append(len(seen))

    p50 = statistics.median(latencies_ms)
    print(f"[List 50/2000 rows + FK + 4 Tabs] queries={max(q_counts)} | p50={p50:.2f} ms")
    assert max(q_counts) <= 4, f"Expected <= 4 queries, got {max(q_counts)}"

    # 4. Streaming CSV Export (2,000 rows) throughput & peak memory
    tracemalloc.start()
    t0 = time.perf_counter()
    exp = client.get("/admin/bench-orders/export.csv")
    csv_bytes = exp.get_data()
    exp_ms = (time.perf_counter() - t0) * 1000.0
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rows_per_sec = 2000 / max(0.001, exp_ms / 1000.0)
    print(
        f"[Stream Export 2000 rows CSV] {len(csv_bytes) / 1024:.1f} KB | "
        f"{exp_ms:.1f} ms ({rows_per_sec:,.0f} rows/s) | peak_mem={peak_bytes / 1024:.0f} KiB"
    )

    # 5. Batched Savepoint Dry-Run Import (1,000 rows: 500 updates + 500 creates)
    buf = io.StringIO()
    buf.write("code,status,amount,org_id\n")
    for i in range(500):
        buf.write(f"ORD-{i:05d},paid,99.99,1\n")
    for i in range(500):
        buf.write(f"ORD-NEW-{i:05d},pending,75.00,2\n")
    payload = buf.getvalue().encode()

    view = deck.get_view("bench-orders")
    with SessionLocal() as sess:
        t0 = time.perf_counter()
        report = run_dry_run_import(
            sess,
            view,
            raw_bytes=payload,
            filename="bench_1k.csv",
            auth=deck.auth,
            user=None,
            upsert_key="code",
        )
        imp_ms = (time.perf_counter() - t0) * 1000.0
        # Verify zero mutations leaked after dry-run!
        total_after = sess.scalar(sa.select(sa.func.count()).select_from(BenchOrder))
        assert total_after == 2000

    print(
        f"[Dry-Run Savepoint Import 1000 rows] creates={report.creates} updates={report.updates} "
        f"unchanged={report.unchanged} errors={report.errors} | {imp_ms:.1f} ms"
    )
    assert report.creates == 500
    assert report.errors == 0

    # 6. Keyset Cursor Pagination Benchmark (zero OFFSET, count_mode='none')
    class BenchCursorOrderView(BenchOrderView):
        slug = "bench-orders-cursor"
        pagination_mode = "cursor"
        count_mode = "none"

    deck.register(BenchCursorOrderView)
    cur_latencies: list[float] = []
    cur_queries: list[int] = []
    for _ in range(15):
        seen_c: list[str] = []

        def _cnt_c(_c: object, _cur: object, stmt: str, *_a: object, _buf: list[str] = seen_c) -> None:
            _buf.append(stmt)

        sa.event.listen(engine, "before_cursor_execute", _cnt_c)
        t0 = time.perf_counter()
        resp = client.get("/admin/bench-orders-cursor/?page_size=50")
        cur_latencies.append((time.perf_counter() - t0) * 1000.0)
        sa.event.remove(engine, "before_cursor_execute", _cnt_c)
        assert resp.status_code == 200
        cur_queries.append(len(seen_c))
    print(
        f"[Keyset Cursor 50/2000 rows (count=none)] queries={max(cur_queries)} | "
        f"p50={statistics.median(cur_latencies):.2f} ms"
    )
    assert max(cur_queries) <= 4
    print("ALL BENCHMARKS PASSED.")


if __name__ == "__main__":
    main()
