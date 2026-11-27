from __future__ import annotations

import fnmatch
import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from flask import (
    Blueprint,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from flask_deck.audit import make_audit_entry
from flask_deck.auth import DeckUser
from flask_deck.exceptions import PermissionDeniedError
from flask_deck.iam import IAMGroupRecord, SQLAlchemyAuthProvider
from flask_deck.mfa import MFA_VERIFIED_KEY
from flask_deck.query import compute_page_window
from flask_deck.sessions import DECK_SID_SESSION_KEY, issue_tracked_session

if TYPE_CHECKING:
    from flask_deck.deck import Deck

_SYSTEM_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("audit:view", "View Audit Ledger"),
    ("rbac:view", "View RBAC Matrix"),
    ("schema:view", "View Schema ERD"),
    ("sql:query", "Run Read-Only SQL Console"),
    ("diagnostics:view", "View Diagnostics"),
    ("webhooks:view", "View Webhook Deliveries"),
    ("approvals:view", "View Approval Queue"),
    ("approvals:review", "Approve / Reject Four-Eyes Requests"),
    ("api_keys:manage", "Manage Scoped API Keys"),
    ("saved_views:manage", "Manage Team & Role Saved Views"),
    ("iam:manage", "Manage Users & Permission Groups"),
    ("*", "Full Superadmin Wildcard (*)"),
)


_PRIVILEGED_SENTINEL = "__deck_superuser_sentinel__:__all__"


def _is_privileged_permission(pattern: str) -> bool:
    """Return True if ``pattern`` grants wildcard/superuser or IAM management privileges."""
    p = pattern.strip()
    if not p:
        return False
    return (
        p in {"*", "**", "*:*", "iam:manage", "iam:*"}
        or fnmatch.fnmatchcase("iam:manage", p)
        or fnmatch.fnmatchcase(_PRIVILEGED_SENTINEL, p)
    )


def _has_privileged_permission(perms: Sequence[str] | frozenset[str]) -> bool:
    return any(_is_privileged_permission(p) for p in perms)


def _is_privileged_user(auth: SQLAlchemyAuthProvider, rec: Any) -> bool:
    """Return True if an IAM user is a superuser or holds wildcard/IAM-admin permissions."""
    if rec.is_superuser or _has_privileged_permission(rec.direct_permissions):
        return True
    for gid in rec.group_ids:
        grec = auth.get_group_record(gid)
        if grec is not None and _has_privileged_permission(grec.permissions):
            return True
    return False


def _parse_direct_permissions(form: Any) -> list[str]:
    perms: list[str] = [p.strip() for p in form.getlist("direct_perm") if p.strip()]
    raw = str(form.get("direct_permissions", ""))
    for line in raw.replace(",", "\n").splitlines():
        tok = line.strip()
        if tok and tok not in perms:
            perms.append(tok)
    return list(dict.fromkeys(perms))


def _parse_group_permissions(form: Any) -> list[str]:
    perms: list[str] = [p.strip() for p in form.getlist("perm") if p.strip()]
    extra_raw = str(form.get("extra_permissions", ""))
    for line in extra_raw.replace(",", "\n").splitlines():
        tok = line.strip()
        if tok and tok not in perms:
            perms.append(tok)
    return list(dict.fromkeys(perms))


def _parse_field_rules_from_form(
    form: Any,
    rule_prefix: str,
    model_slugs: Sequence[str],
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    json_raw = str(form.get(f"{rule_prefix}_json", "")).strip()
    if json_raw and json_raw != "{}":
        try:
            parsed = json.loads(json_raw)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid JSON in {rule_prefix}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"{rule_prefix} JSON must be an object mapping model_slug -> fields.")
        for k, v in parsed.items():
            if isinstance(k, str) and isinstance(v, list):
                fields = [str(x).strip() for x in v if str(x).strip()]
                if fields:
                    out[k.strip()] = fields
        return out

    for slug in model_slugs:
        raw = str(form.get(f"{rule_prefix}__{slug}", "")).strip()
        if raw:
            fields = [f.strip() for f in raw.split(",") if f.strip()]
            if fields:
                out[slug] = fields
    return out


def register_iam_routes(bp: Blueprint, deck: Deck) -> None:
    """Register optional DB-backed IAM routes (users, groups, self-service password)."""
    from flask_deck.deck import _client_ip

    bp_name = deck.config.name

    def _require_iam_admin() -> tuple[SQLAlchemyAuthProvider, DeckUser]:
        if not isinstance(deck.auth, SQLAlchemyAuthProvider):
            abort(404)
        if getattr(g, "_deck_real_user", None) is not None:
            raise PermissionDeniedError(
                "IAM users and groups cannot be managed while impersonating another user."
            )
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "iam:manage")
        ):
            raise PermissionDeniedError("Missing permission: iam:manage")
        return deck.auth, user

    def _audit(
        actor: DeckUser,
        *,
        action: str,
        record_pk: str,
        record_repr: str,
        changes: dict[str, dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if deck.audit_store is not None and deck.config.auto_audit:
            meta = dict(metadata or {})
            real = getattr(g, "_deck_real_user", None)
            if real is not None and getattr(real, "id", None) != actor.id:
                meta["impersonated_by"] = real.id
                meta["impersonated_by_name"] = real.label
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=actor.id,
                    actor_name=actor.label,
                    actor_ip=_client_ip(),
                    action=action,
                    model_slug="_security",
                    model_label="IAM Security",
                    record_pk=record_pk,
                    record_repr=record_repr,
                    changes=changes or {},
                    metadata=meta,
                )
            )

    @bp.route("/_security/password", methods=["GET", "POST"])
    def security_change_password() -> Any:
        if getattr(g, "_deck_real_user", None) is not None:
            raise PermissionDeniedError(
                "Password cannot be changed while impersonating another user."
            )
        user = deck._current_user()
        if user is None or not deck.auth.supports_password_change:
            abort(404)

        if request.method == "POST":
            cur_pwd = request.form.get("current_password", "")
            new_pwd = request.form.get("new_password", "")
            confirm_pwd = request.form.get("confirm_password", "")
            if new_pwd != confirm_pwd:
                flash("New password and confirmation do not match.", "danger")
                return redirect(url_for(f"{bp_name}.security_change_password"))
            ok, msg = deck.auth.change_password(user.id, cur_pwd, new_pwd)
            if not ok:
                flash(msg, "danger")
                return redirect(url_for(f"{bp_name}.security_change_password"))

            was_mfa = bool(session.get(MFA_VERIFIED_KEY))
            deck.auth.login_user(user)
            if was_mfa:
                session[MFA_VERIFIED_KEY] = True
            if deck.session_store is not None:
                issue_tracked_session(
                    deck.session_store,
                    user_id=user.id,
                    username=user.username,
                    ip_address=_client_ip(),
                    user_agent=str(request.headers.get("User-Agent", "")),
                )
                new_sid = session.get(DECK_SID_SESSION_KEY)
                deck.session_store.revoke_others(
                    user.id, keep_session_id=str(new_sid) if isinstance(new_sid, str) else None
                )
            _audit(
                user,
                action="password_changed",
                record_pk=user.id,
                record_repr=user.username,
                metadata={"self_service": True},
            )
            flash("Password updated. Other active sessions were signed out.", "ok")
            return redirect(url_for(f"{bp_name}.index"))

        return render_template(
            "flask_deck/change_password.html",
            **deck._base_context(
                page_title="Change Password",
                active_nav="_password",
            ),
        )

    @bp.route("/_security/users")
    def security_iam_users() -> str:
        auth, _ = _require_iam_admin()
        q = request.args.get("q", "").strip()
        status = request.args.get("status", "").strip().lower()
        group_id = request.args.get("group_id", "").strip()
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        page_size = 25
        users_page, total_users = auth.list_users_paginated(
            q=q,
            status=status,
            group_id=group_id,
            page=page,
            page_size=page_size,
        )
        pages = max(1, (total_users + page_size - 1) // page_size)
        if page > pages:
            page = pages
        edit_id = request.args.get("edit", "").strip()
        editing_user = auth.get_user_record(edit_id) if edit_id else None
        editing_direct_perms_text = (
            "\n".join(sorted(editing_user.direct_permissions)) if editing_user is not None else ""
        )
        return render_template(
            "flask_deck/iam_users.html",
            **deck._base_context(
                page_title="Users",
                active_nav="_iam_users",
                users=users_page,
                total_users=total_users,
                page=page,
                pages=pages,
                page_window=compute_page_window(page, pages),
                filter_q=q,
                filter_status=status,
                filter_group_id=group_id,
                groups=auth.list_groups(),
                editing_user=editing_user,
                editing_direct_perms_text=editing_direct_perms_text,
                password_rules=auth.password_help_texts(),
            ),
        )

    @bp.route("/_security/users/create", methods=["POST"])
    def security_iam_user_create() -> Any:
        auth, actor = _require_iam_admin()
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        tenant_id = request.form.get("tenant_id", "").strip() or None
        is_active = request.form.get("is_active") in {"1", "true", "on"}
        want_super = request.form.get("is_superuser") in {"1", "true", "on"}
        if want_super and not actor.is_superuser:
            raise PermissionDeniedError("Only a superuser may grant superuser privileges.")
        group_ids = [g_id.strip() for g_id in request.form.getlist("group_ids") if g_id.strip()]
        direct_perms = _parse_direct_permissions(request.form)
        if not actor.is_superuser:
            if _has_privileged_permission(direct_perms):
                raise PermissionDeniedError(
                    "Only a superuser may grant wildcard or 'iam:manage' permissions."
                )
            for gid in group_ids:
                grec = auth.get_group_record(gid)
                if grec is not None and _has_privileged_permission(grec.permissions):
                    raise PermissionDeniedError(
                        "Only a superuser may assign groups containing wildcard or 'iam:manage' permissions."
                    )
        try:
            created = auth.create_user(
                username=username,
                password=password,
                display_name=display_name,
                email=email,
                is_active=is_active,
                is_superuser=want_super,
                group_ids=group_ids,
                direct_permissions=direct_perms,
                tenant_id=tenant_id,
            )
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users"))

        _audit(
            actor,
            action="iam.user_created",
            record_pk=created.id,
            record_repr=created.username,
            metadata={
                "roles": list(created.role_names),
                "direct_permissions": sorted(created.direct_permissions),
                "is_superuser": created.is_superuser,
            },
        )
        flash(f"Created user '{created.username}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_users"))

    @bp.route("/_security/users/<user_id>/update", methods=["POST"])
    def security_iam_user_update(user_id: str) -> Any:
        auth, actor = _require_iam_admin()
        existing = auth.get_user_record(user_id)
        if existing is None:
            abort(404)
        if _is_privileged_user(auth, existing) and not actor.is_superuser:
            raise PermissionDeniedError(
                "Only a superuser may modify a superuser or privileged IAM account."
            )
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip()
        tenant_id = request.form.get("tenant_id", "")
        is_active = request.form.get("is_active") in {"1", "true", "on"}
        want_super = request.form.get("is_superuser") in {"1", "true", "on"}
        if want_super and not actor.is_superuser:
            raise PermissionDeniedError("Only a superuser may grant superuser privileges.")
        group_ids = [g_id.strip() for g_id in request.form.getlist("group_ids") if g_id.strip()]
        has_direct_field = (
            "direct_permissions" in request.form or "direct_perm" in request.form
        )
        direct_perms: list[str] | None = (
            _parse_direct_permissions(request.form) if has_direct_field else None
        )
        if not actor.is_superuser:
            if direct_perms is not None and _has_privileged_permission(direct_perms):
                raise PermissionDeniedError(
                    "Only a superuser may grant wildcard or 'iam:manage' permissions."
                )
            existing_gids = set(existing.group_ids)
            for gid in group_ids:
                grec = auth.get_group_record(gid)
                if grec is not None and _has_privileged_permission(grec.permissions) and gid not in existing_gids:
                    raise PermissionDeniedError(
                        "Only a superuser may assign groups containing wildcard or 'iam:manage' permissions."
                    )
        try:
            updated = auth.update_user(
                user_id,
                display_name=display_name,
                email=email,
                is_active=is_active,
                is_superuser=want_super,
                group_ids=group_ids,
                direct_permissions=direct_perms,
                tenant_id=tenant_id,
            )
        except (ValueError, KeyError) as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users", edit=user_id))

        if not updated.is_active and deck.session_store is not None:
            deck.session_store.revoke_others(user_id, keep_session_id=None)

        _audit(
            actor,
            action="iam.user_updated",
            record_pk=updated.id,
            record_repr=updated.username,
            metadata={
                "is_active": updated.is_active,
                "is_superuser": updated.is_superuser,
                "roles": list(updated.role_names),
                "direct_permissions": sorted(updated.direct_permissions),
            },
        )
        flash(f"Updated user '{updated.username}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_users"))

    @bp.route("/_security/users/bulk", methods=["POST"])
    def security_iam_users_bulk() -> Any:
        auth, actor = _require_iam_admin()
        act = request.form.get("action", "").strip().lower()
        if act not in {"activate", "deactivate"}:
            flash("Select a valid bulk action (activate or deactivate).", "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users"))
        selected_ids = [uid.strip() for uid in request.form.getlist("user_ids") if uid.strip()]
        if not selected_ids:
            flash("Select at least one user.", "warn")
            return redirect(url_for(f"{bp_name}.security_iam_users"))
        if not actor.is_superuser:
            for uid in selected_ids:
                target = auth.get_user_record(uid)
                if target is not None and _is_privileged_user(auth, target):
                    raise PermissionDeniedError(
                        "Only a superuser may modify superuser or privileged IAM accounts."
                    )
        target_active = act == "activate"
        try:
            updated_ids = auth.bulk_set_active(selected_ids, is_active=target_active)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users"))
        if not target_active and deck.session_store is not None:
            for uid in updated_ids:
                deck.session_store.revoke_others(uid, keep_session_id=None)
        _audit(
            actor,
            action=f"iam.users_bulk_{act}",
            record_pk=",".join(updated_ids[:10]),
            record_repr=f"Bulk {act} ({len(updated_ids)} user(s))",
            metadata={"action": act, "count": len(updated_ids)},
        )
        verb = "Activated" if target_active else "Deactivated"
        flash(f"{verb} {len(updated_ids)} user account(s).", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_users"))

    @bp.route("/_security/users/<user_id>/reset-password", methods=["POST"])
    def security_iam_user_reset_password(user_id: str) -> Any:
        auth, actor = _require_iam_admin()
        existing = auth.get_user_record(user_id)
        if existing is None:
            abort(404)
        if _is_privileged_user(auth, existing) and not actor.is_superuser:
            raise PermissionDeniedError(
                "Only a superuser may reset a superuser or privileged IAM account password."
            )
        new_pwd = request.form.get("new_password", "")
        try:
            auth.admin_reset_password(user_id, new_pwd)
        except (ValueError, KeyError) as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users", edit=user_id))

        if deck.session_store is not None:
            deck.session_store.revoke_others(user_id, keep_session_id=None)

        _audit(
            actor,
            action="iam.password_reset",
            record_pk=existing.id,
            record_repr=existing.username,
            metadata={"sessions_revoked": deck.session_store is not None},
        )
        flash(f"Reset password for '{existing.username}' and revoked active sessions.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_users"))

    @bp.route("/_security/users/<user_id>/delete", methods=["POST"])
    def security_iam_user_delete(user_id: str) -> Any:
        auth, actor = _require_iam_admin()
        existing = auth.get_user_record(user_id)
        if existing is None:
            abort(404)
        if _is_privileged_user(auth, existing) and not actor.is_superuser:
            raise PermissionDeniedError(
                "Only a superuser may delete a superuser or privileged IAM account."
            )
        try:
            auth.delete_user(user_id)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_users"))

        if deck.session_store is not None:
            deck.session_store.revoke_others(user_id, keep_session_id=None)
        if deck.api_key_store is not None:
            for key_rec in deck.api_key_store.list_keys(owner_id=user_id, limit=500):
                deck.api_key_store.revoke(key_rec.id, owner_id=user_id)

        _audit(
            actor,
            action="iam.user_deleted",
            record_pk=existing.id,
            record_repr=existing.username,
        )
        flash(f"Deleted user '{existing.username}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_users"))

    @bp.route("/_security/groups")
    def security_iam_groups() -> str:
        auth, _ = _require_iam_admin()
        edit_id = request.args.get("edit", "").strip()
        editing_group: IAMGroupRecord | None = auth.get_group_record(edit_id) if edit_id else None
        model_specs = [
            {
                "slug": v.meta.slug,
                "label": v.plural_label,
                "fields": [f.name for f in v.meta.fields if not f.is_sensitive],
            }
            for v in deck.views.values()
        ]
        builtin_set = {p[0] for p in _SYSTEM_PERMISSIONS}
        for ms in model_specs:
            for act in ("view", "create", "edit", "delete", "export", "import"):
                builtin_set.add(f"{ms['slug']}:{act}")

        extra_perms_text = ""
        hidden_json = "{}"
        readonly_json = "{}"
        masked_json = "{}"
        if editing_group is not None:
            extra_perms_text = "\n".join(
                sorted(p for p in editing_group.permissions if p not in builtin_set)
            )
            hidden_json = json.dumps(
                {k: sorted(v) for k, v in editing_group.hidden_fields.items()}, indent=2
            )
            readonly_json = json.dumps(
                {k: sorted(v) for k, v in editing_group.readonly_fields.items()}, indent=2
            )
            masked_json = json.dumps(
                {k: sorted(v) for k, v in editing_group.masked_fields.items()}, indent=2
            )

        return render_template(
            "flask_deck/iam_groups.html",
            **deck._base_context(
                page_title="Groups & Roles",
                active_nav="_iam_groups",
                groups=auth.list_groups(),
                editing_group=editing_group,
                model_specs=model_specs,
                system_permissions=_SYSTEM_PERMISSIONS,
                extra_perms_text=extra_perms_text,
                hidden_json=hidden_json,
                readonly_json=readonly_json,
                masked_json=masked_json,
            ),
        )

    @bp.route("/_security/groups/create", methods=["POST"])
    def security_iam_group_create() -> Any:
        auth, actor = _require_iam_admin()
        name = request.form.get("name", "").strip()
        label = request.form.get("label", "").strip()
        description = request.form.get("description", "").strip()
        perms = _parse_group_permissions(request.form)
        if not actor.is_superuser and _has_privileged_permission(perms):
            raise PermissionDeniedError(
                "Only a superuser may grant wildcard or 'iam:manage' permissions."
            )
        model_slugs = list(deck.views.keys())
        try:
            hidden_r = _parse_field_rules_from_form(request.form, "hidden_fields", model_slugs)
            ro_r = _parse_field_rules_from_form(request.form, "readonly_fields", model_slugs)
            masked_r = _parse_field_rules_from_form(request.form, "masked_fields", model_slugs)
            created = auth.create_group(
                name=name,
                label=label,
                description=description,
                permissions=perms,
                hidden_fields=hidden_r,
                readonly_fields=ro_r,
                masked_fields=masked_r,
            )
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_groups"))

        _audit(
            actor,
            action="iam.group_created",
            record_pk=created.id,
            record_repr=created.name,
            metadata={"permissions_count": len(created.permissions)},
        )
        flash(f"Created permission group '{created.name}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_groups"))

    @bp.route("/_security/groups/<group_id>/update", methods=["POST"])
    def security_iam_group_update(group_id: str) -> Any:
        auth, actor = _require_iam_admin()
        existing = auth.get_group_record(group_id)
        if existing is None:
            abort(404)
        if not actor.is_superuser and _has_privileged_permission(existing.permissions):
            raise PermissionDeniedError(
                "Only a superuser may modify a group containing wildcard or 'iam:manage' permissions."
            )
        label = request.form.get("label", "").strip()
        description = request.form.get("description", "").strip()
        perms = _parse_group_permissions(request.form)
        if not actor.is_superuser and _has_privileged_permission(perms):
            raise PermissionDeniedError(
                "Only a superuser may grant wildcard or 'iam:manage' permissions."
            )
        model_slugs = list(deck.views.keys())
        try:
            hidden_r = _parse_field_rules_from_form(request.form, "hidden_fields", model_slugs)
            ro_r = _parse_field_rules_from_form(request.form, "readonly_fields", model_slugs)
            masked_r = _parse_field_rules_from_form(request.form, "masked_fields", model_slugs)
            updated = auth.update_group(
                group_id,
                label=label,
                description=description,
                permissions=perms,
                hidden_fields=hidden_r,
                readonly_fields=ro_r,
                masked_fields=masked_r,
            )
        except (ValueError, KeyError) as exc:
            flash(str(exc), "danger")
            return redirect(url_for(f"{bp_name}.security_iam_groups", edit=group_id))

        _audit(
            actor,
            action="iam.group_updated",
            record_pk=updated.id,
            record_repr=updated.name,
            metadata={"permissions_count": len(updated.permissions)},
        )
        flash(f"Updated group '{updated.name}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_groups"))

    @bp.route("/_security/groups/<group_id>/delete", methods=["POST"])
    def security_iam_group_delete(group_id: str) -> Any:
        auth, actor = _require_iam_admin()
        existing = auth.get_group_record(group_id)
        if existing is None:
            abort(404)
        if not actor.is_superuser and _has_privileged_permission(existing.permissions):
            raise PermissionDeniedError(
                "Only a superuser may delete a group containing wildcard or 'iam:manage' permissions."
            )
        auth.delete_group(group_id)
        _audit(
            actor,
            action="iam.group_deleted",
            record_pk=existing.id,
            record_repr=existing.name,
        )
        flash(f"Deleted permission group '{existing.name}'.", "ok")
        return redirect(url_for(f"{bp_name}.security_iam_groups"))
