from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

import pytest
import sqlalchemy as sa
from flask import Flask
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import StaticPool

from flask_deck import (
    Deck,
    DeckUser,
    Fieldset,
    InlineModelView,
    InMemoryAuditStore,
    ModelView,
    RBACAuthProvider,
    Role,
    display,
)
from tests.conftest import login_as


class AuthBase(DeclarativeBase):
    pass


class Dept(AuthBase):
    __tablename__ = "v05_a_depts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(80), nullable=False)
    slug: Mapped[str] = mapped_column(sa.String(80), unique=True, nullable=False)
    tenant_id: Mapped[int] = mapped_column(sa.Integer, default=1, nullable=False)

    def __str__(self) -> str:
        return self.name


class SkillTag(AuthBase):
    __tablename__ = "v05_a_tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(60), nullable=False)

    def __str__(self) -> str:
        return self.name


proj_skill_tbl = sa.Table(
    "v05_a_proj_tags",
    AuthBase.metadata,
    sa.Column("project_id", sa.ForeignKey("v05_a_projects.id"), primary_key=True),
    sa.Column("tag_id", sa.ForeignKey("v05_a_tags.id"), primary_key=True),
)


class Project(AuthBase):
    __tablename__ = "v05_a_projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    slug: Mapped[str] = mapped_column(sa.String(100), nullable=False)
    budget: Mapped[int] = mapped_column(sa.Integer, default=1000, nullable=False)
    immutable_code: Mapped[str] = mapped_column(sa.String(40), default="LOCK-001", nullable=False)
    external_url: Mapped[str | None] = mapped_column(sa.String(200), nullable=True)
    dept_id: Mapped[int] = mapped_column(sa.ForeignKey("v05_a_depts.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    dept: Mapped[Dept] = relationship()
    skills: Mapped[list[SkillTag]] = relationship(secondary=proj_skill_tbl)
    tasks: Mapped[list[ProjectTask]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )

    def __str__(self) -> str:
        return f"{self.name} ({self.slug})"


class ProjectTask(AuthBase):
    __tablename__ = "v05_a_tasks"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(sa.ForeignKey("v05_a_projects.id"), nullable=False)
    title: Mapped[str] = mapped_column(sa.String(120), nullable=False, info={"help_text": "Task summary"})
    done: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    project: Mapped[Project] = relationship(back_populates="tasks")


class ProjectTaskInline(InlineModelView):
    model = ProjectTask
    layout = "stacked"
    min_num = 1
    extra = 1
    show_change_link = True
    columns = ("title", "done")


class DeptView(ModelView):
    model = Dept
    slug = "depts"

    def scope_query(self, stmt: sa.Select[Any], user: DeckUser | None) -> sa.Select[Any]:
        if user is not None and not user.is_superuser and user.tenant_id is not None:
            return stmt.where(Dept.tenant_id == user.tenant_id)
        return stmt


class SkillTagView(ModelView):
    model = SkillTag
    slug = "skill-tags"


class ProjectTaskView(ModelView):
    model = ProjectTask
    slug = "project-tasks"


class ProjectView(ModelView):
    model = Project
    slug = "projects"
    columns = ("name", "slug", "budget", "budget_tier", "external_url", "created_at")
    readonly_fields = ("immutable_code", "created_at")
    empty_value_display = "N/A"
    save_as = True
    preserve_filters = True
    m2m_mode = "dual"
    search_help_text = "Find project by title or URL slug"
    field_help_texts = MappingProxyType({"slug": "URL-safe kebab identifier."})
    prepopulated_fields = MappingProxyType({"slug": ("name",)})
    view_on_site = staticmethod(lambda obj: obj.external_url)
    inlines = (ProjectTaskInline,)
    fieldsets = (
        Fieldset(
            "Core Details",
            (("name", "slug"), "dept_id", "skills"),
            description="Horizontal title + slug row.",
        ),
        Fieldset(
            "Budget & Governance",
            ("budget", "immutable_code", "external_url", "created_at"),
            collapsible=True,
            collapsed=True,
        ),
    )

    @display(label="Budget Tier", ordering="budget", description="Computed tier badge")
    def budget_tier(self, obj: Project) -> str:
        return "ENTERPRISE" if obj.budget >= 5000 else "STANDARD"


@pytest.fixture()
def author_app() -> Iterator[tuple[Flask, Deck, sessionmaker[Any], InMemoryAuditStore]]:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "authoring-v05-secret-key-at-least-32bytes"
    app.config["TESTING"] = True
    engine = sa.create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    AuthBase.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with SessionLocal() as sess:
        d1 = Dept(name="Platform Eng", slug="platform-eng", tenant_id=1)
        d2 = Dept(name="Secret Ops", slug="secret-ops", tenant_id=2)
        tags = [SkillTag(name="Python"), SkillTag(name="Postgres"), SkillTag(name="Rust")]
        sess.add_all([d1, d2, *tags])
        sess.flush()
        p1 = Project(
            name="Core Router",
            slug="core-router",
            budget=2000,
            external_url="https://example.com/core",
            dept_id=d1.id,
            skills=[tags[0]],
        )
        p2 = Project(
            name="Unsafe Site",
            slug="unsafe-site",
            budget=9000,
            external_url="javascript:alert(1)",
            dept_id=d1.id,
        )
        sess.add_all([p1, p2])
        sess.flush()
        sess.add(ProjectTask(project_id=p1.id, title="Bootstrap edge", done=True))
        sess.commit()

    auth = RBACAuthProvider(
        roles=[
            Role(name="admin", permissions=frozenset({"*"})),
            Role(
                name="editor",
                permissions=frozenset({"projects:*", "depts:view", "depts:edit"}),
            ),
        ],
        accounts=[
            RBACAuthProvider.make_account(
                user=DeckUser(id="a1", username="admin", roles=("admin",), is_superuser=True),
                password="admin-password",
            ),
            RBACAuthProvider.make_account(
                user=DeckUser(
                    id="e1",
                    username="t1_editor",
                    roles=("editor",),
                    tenant_id=1,
                ),
                password="editor-password",
            ),
        ],
    )
    audit = InMemoryAuditStore()
    deck = Deck(app, session_factory=SessionLocal, engine=engine, auth=auth, audit_store=audit)
    deck.register(DeptView, SkillTagView, ProjectTaskView, ProjectView)
    yield app, deck, SessionLocal, audit
    deck.close()
    engine.dispose()


def test_m1_display_fieldsets_help_readonly_view_on_site(
    author_app: tuple[Flask, Deck, sessionmaker[Any], InMemoryAuditStore],
) -> None:
    app, _, SessionLocal, _ = author_app
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # @display renders + SQL ordering sort works + empty_value_display + search_help_text
    list_html = client.get("/admin/projects/?sort=budget_tier&dir=asc").get_data(as_text=True)
    assert "Budget Tier" in list_html
    assert "STANDARD" in list_html
    assert "ENTERPRISE" in list_html
    assert "Find project by title or URL slug" in list_html
    assert "N/A" not in list_html or "external_url" in list_html

    # Valid view_on_site renders on detail, unsafe javascript: rejected cleanly
    d1_html = client.get("/admin/projects/1").get_data(as_text=True)
    assert "https://example.com/core" in d1_html
    assert "View on Site" in d1_html
    d2_html = client.get("/admin/projects/2").get_data(as_text=True)
    assert 'href="javascript:' not in d2_html
    assert "View on Site" not in d2_html

    # Form renders Fieldsets (horizontal + collapsible <details>), prepopulated_fields, help_text, dual M2M, stacked inline
    new_html = client.get("/admin/projects/new").get_data(as_text=True)
    assert "dk-field-row" in new_html
    assert "<details class=\"dk-panel dk-fieldset-details\"" in new_html
    assert "URL-safe kebab identifier." in new_html
    assert "data-prepopulate-from=" in new_html
    assert "dk-m2m-dual" in new_html
    assert "dk-inline-card" in new_html

    # Mass-assignment attempt against readonly_fields (`immutable_code`) is blocked on BOTH create & edit
    res_create = client.post(
        "/admin/projects/new",
        data={
            "_csrf_token": csrf,
            "name": "Blocked Tamper",
            "slug": "blocked-tamper",
            "budget": "4200",
            "dept_id": "1",
            "immutable_code": "HACKED-999",
            "inline__project-tasks__0__title": "Mandatory task",
            "inline__project-tasks__0__done": "false",
        },
        follow_redirects=False,
    )
    assert res_create.status_code == 302
    with SessionLocal() as sess:
        created = sess.scalar(sa.select(Project).where(Project.slug == "blocked-tamper"))
        assert created is not None
        assert created.immutable_code == "LOCK-001"
        created_id = created.id

    d3_html = client.get(f"/admin/projects/{created_id}").get_data(as_text=True)
    assert "N/A" in d3_html
    assert "N/A" in client.get("/admin/projects/").get_data(as_text=True)

    res_edit = client.post(
        f"/admin/projects/{created_id}/edit",
        data={
            "_csrf_token": csrf,
            "name": "Blocked Tamper Edit",
            "slug": "blocked-tamper",
            "budget": "4500",
            "dept_id": "1",
            "immutable_code": "TAMPER-AGAIN",
            "inline__project-tasks__0__title": "Still here",
            "inline__project-tasks__0__done": "false",
        },
        follow_redirects=False,
    )
    assert res_edit.status_code == 302
    with SessionLocal() as sess:
        reloaded = sess.get(Project, created_id)
        assert reloaded is not None
        assert reloaded.immutable_code == "LOCK-001"


def test_m2_save_actions_return_qs_and_inlines(
    author_app: tuple[Flask, Deck, sessionmaker[Any], InMemoryAuditStore],
) -> None:
    app, _, SessionLocal, _ = author_app
    client = app.test_client()
    csrf = login_as(client, "admin", "admin-password")

    # Inline min_num=1 validation enforcement
    bad_min = client.post(
        "/admin/projects/new",
        data={
            "_csrf_token": csrf,
            "name": "No Tasks",
            "slug": "no-tasks",
            "budget": "100",
            "dept_id": "1",
        },
        follow_redirects=False,
    )
    assert bad_min.status_code == 200
    assert "At least 1" in bad_min.get_data(as_text=True)

    # Boolean unchecked false + checked true inline handling + _save_action=continue
    cont = client.post(
        "/admin/projects/1/edit",
        data={
            "_csrf_token": csrf,
            "_save_action": "continue",
            "_return_qs": "q=Core&page=2",
            "name": "Core Router v2",
            "slug": "core-router",
            "budget": "2500",
            "dept_id": "1",
            "inline__project-tasks__0___pk": "1",
            "inline__project-tasks__0__title": "Bootstrap edge",
            "inline__project-tasks__0__done": "true",
        },
        follow_redirects=False,
    )
    assert cont.status_code == 302
    assert "/admin/projects/1/edit" in cont.headers["Location"]
    assert "_return_qs=q%3DCore%26page%3D2" in cont.headers["Location"]

    # _save_action=save_as clones record AND its inline rows cleanly
    save_as = client.post(
        "/admin/projects/1/edit",
        data={
            "_csrf_token": csrf,
            "_save_action": "save_as",
            "_return_qs": "q=Core",
            "name": "Core Router Clone",
            "slug": "core-router-clone",
            "budget": "3100",
            "dept_id": "1",
            "inline__project-tasks__0___pk": "1",
            "inline__project-tasks__0__title": "Cloned inline task",
            "inline__project-tasks__0__done": ["false"],
        },
        follow_redirects=False,
    )
    assert save_as.status_code == 302
    with SessionLocal() as sess:
        clone_obj = sess.scalar(sa.select(Project).where(Project.slug == "core-router-clone"))
        assert clone_obj is not None
        assert clone_obj.id != 1
        assert len(clone_obj.tasks) == 1
        assert clone_obj.tasks[0].title == "Cloned inline task"
        assert clone_obj.tasks[0].done is False
        orig_task = sess.get(ProjectTask, 1)
        assert orig_task is not None and orig_task.title == "Bootstrap edge"

    # Open-redirect injection via _return_qs is neutralized
    safe_save = client.post(
        "/admin/projects/new",
        data={
            "_csrf_token": csrf,
            "_save_action": "save",
            "_return_qs": "//evil.example/phish",
            "name": "Safe Redirect",
            "slug": "safe-redirect",
            "budget": "1000",
            "dept_id": "1",
            "inline__project-tasks__0__title": "Check redirect",
            "inline__project-tasks__0__done": "false",
        },
        follow_redirects=False,
    )
    assert safe_save.status_code == 302
    assert "evil.example" not in safe_save.headers["Location"]
    assert safe_save.headers["Location"].endswith("/admin/projects/")


def test_m2_slide_over_drawer_quick_create_edit_and_tenant_guard(
    author_app: tuple[Flask, Deck, sessionmaker[Any], InMemoryAuditStore],
) -> None:
    app, _, SessionLocal, audit = author_app
    admin = app.test_client()
    a_csrf = login_as(admin, "admin", "admin-password")

    # GET quick-create partial
    r_get = admin.get("/admin/_api/skill-tags/quick-create")
    assert r_get.status_code == 200
    assert "data-deck-quick-form" in r_get.get_data(as_text=True)

    # POST quick-create JSON 201 + audit entry
    r_post = admin.post(
        "/admin/_api/skill-tags/quick-create",
        data={"_csrf_token": a_csrf, "name": "GraphQL"},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_post.status_code == 201
    payload = r_post.get_json()
    assert payload["ok"] is True
    assert payload["label"] == "GraphQL"

    # GET/POST quick-edit-form
    r_ed = admin.post(
        f"/admin/_api/skill-tags/{payload['id']}/quick-edit-form",
        data={"_csrf_token": a_csrf, "name": "GraphQL Federation"},
        headers={"X-Deck-CSRFToken": a_csrf},
    )
    assert r_ed.status_code == 200
    assert r_ed.get_json()["label"] == "GraphQL Federation"
    assert any(e.metadata.get("quick_drawer") for e in audit.list_entries()[0])

    # Missing CSRF -> 403 JSON on api_*
    r_no_csrf = admin.post("/admin/_api/skill-tags/quick-create", data={"name": "Bypass"})
    assert r_no_csrf.status_code == 403

    # Tenant editor without skill-tags:create gets 403, and cannot quick-edit out-of-tenant dept #2
    ed = app.test_client()
    e_csrf = login_as(ed, "t1_editor", "editor-password")
    assert ed.get("/admin/_api/skill-tags/quick-create").status_code == 403
    r_cross = ed.post(
        "/admin/_api/depts/2/quick-edit-form",
        data={"_csrf_token": e_csrf, "name": "Hacked", "slug": "hacked", "tenant_id": "1"},
        headers={"X-Deck-CSRFToken": e_csrf},
    )
    assert r_cross.status_code == 404
    with SessionLocal() as sess:
        assert sess.get(Dept, 2).name == "Secret Ops"  # type: ignore[union-attr]
