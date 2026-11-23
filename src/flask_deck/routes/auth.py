from __future__ import annotations

import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from flask import (
    Blueprint,
    Response,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup

from flask_deck.api_keys import build_api_key_record
from flask_deck.audit import make_audit_entry
from flask_deck.auth import DeckUser, RBACAuthProvider
from flask_deck.exceptions import PermissionDeniedError
from flask_deck.mfa import (
    MFA_PENDING_AT_KEY,
    MFA_PENDING_NEXT_KEY,
    MFA_PENDING_SSO_KEY,
    MFA_PENDING_USER_KEY,
    MFA_VERIFIED_KEY,
    MFAEnrollment,
    build_otpauth_uri,
    generate_recovery_codes,
    generate_totp_secret,
    render_qr_svg,
    verify_totp,
)
from flask_deck.passkeys import (
    PASSKEY_AUTH_CHALLENGE_KEY,
    PASSKEY_REG_CHALLENGE_KEY,
    begin_passkey_authentication,
    begin_passkey_registration,
    complete_passkey_authentication,
    complete_passkey_registration,
    is_webauthn_available,
)
from flask_deck.security import is_safe_redirect_url, rotate_csrf_token
from flask_deck.sessions import DECK_SID_SESSION_KEY, issue_tracked_session
from flask_deck.sso import OIDCAuthProvider

if TYPE_CHECKING:
    from flask_deck.deck import Deck


def register_auth_routes(bp: Blueprint, deck: Deck) -> None:
    """Register authentication, MFA, OIDC SSO, impersonation, and demo switcher routes."""
    from flask_deck.deck import (
        IMPERSONATE_RO_KEY,
        IMPERSONATED_USER_KEY,
        IMPERSONATOR_USER_KEY,
        MFA_PENDING_TTL_SECONDS,
        MFA_SETUP_SECRET_KEY,
        _client_ip,
    )

    bp_name = deck.config.name

    def _track_session(user: DeckUser) -> None:
        if deck.session_store is not None:
            issue_tracked_session(
                deck.session_store,
                user_id=user.id,
                username=user.username,
                ip_address=_client_ip(),
                user_agent=str(request.headers.get("User-Agent", "")),
            )

    def _rp_id_and_origin() -> tuple[str, str]:
        host = request.host.split(":")[0] or "localhost"
        origin = request.host_url.rstrip("/")
        return host, origin

    @bp.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        if not deck.auth.supports_login_form:
            abort(404)
        if deck._current_user() is not None:
            return redirect(url_for(f"{bp_name}.index"))

        next_url = request.args.get("next") or request.form.get("next") or ""
        error_msg = ""

        if request.method == "POST":
            if not deck.auth.supports_password_login:
                abort(403, description="Password login is disabled; use SSO or Passkey.")
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            ip = _client_ip()
            locked, retry_after = deck._rate_limiter.is_locked(ip, username)
            if locked:
                error_msg = f"Too many failed attempts. Try again in {retry_after}s."
                resp = Response(
                    render_template(
                        "flask_deck/login.html",
                        **deck._base_context(
                            next_url=next_url,
                            error_msg=error_msg,
                            demo_credentials=deck._demo_credentials,
                        ),
                    ),
                    status=429,
                )
                resp.headers["Retry-After"] = str(retry_after)
                return resp

            user = deck.auth.authenticate(username, password)
            if user is not None:
                deck._rate_limiter.record_success(ip, username)
                dest = next_url if is_safe_redirect_url(next_url) else url_for(f"{bp_name}.index")
                if deck.mfa_store is not None:
                    enrollment = deck.mfa_store.get(user.id)
                    if enrollment is not None and enrollment.enabled:
                        session.clear()
                        session[MFA_PENDING_USER_KEY] = user.id
                        session[MFA_PENDING_NEXT_KEY] = dest
                        session[MFA_PENDING_AT_KEY] = int(time.time())
                        rotate_csrf_token()
                        return redirect(url_for(f"{bp_name}.login_mfa"))
                deck.auth.login_user(user)
                _track_session(user)
                return redirect(dest)

            deck._rate_limiter.record_failure(ip, username)
            deck._emit_event("login.failed", payload={"username": username, "ip": ip})
            error_msg = "Invalid username or password."

        return render_template(
            "flask_deck/login.html",
            **deck._base_context(
                next_url=next_url,
                error_msg=error_msg,
                demo_credentials=deck._demo_credentials,
            ),
        )

    @bp.route("/login/mfa", methods=["GET", "POST"])
    def login_mfa() -> Any:
        if deck.mfa_store is None:
            abort(404)
        pending_uid = session.get(MFA_PENDING_USER_KEY)
        pending_at = session.get(MFA_PENDING_AT_KEY)
        if not isinstance(pending_uid, str) or not pending_uid:
            return redirect(url_for(f"{bp_name}.login"))
        if isinstance(pending_at, int) and (int(time.time()) - pending_at) > MFA_PENDING_TTL_SECONDS:
            session.pop(MFA_PENDING_USER_KEY, None)
            session.pop(MFA_PENDING_NEXT_KEY, None)
            session.pop(MFA_PENDING_AT_KEY, None)
            session.pop(MFA_PENDING_SSO_KEY, None)
            flash("MFA verification window expired. Please sign in again.", "warn")
            return redirect(url_for(f"{bp_name}.login"))

        error_msg = ""
        if request.method == "POST":
            ip = _client_ip()
            locked, retry_after = deck._rate_limiter.is_locked(ip, f"mfa:{pending_uid}")
            if locked:
                resp = Response(
                    render_template(
                        "flask_deck/login_mfa.html",
                        **deck._base_context(
                            error_msg=f"Too many failed MFA attempts. Retry in {retry_after}s."
                        ),
                    ),
                    status=429,
                )
                resp.headers["Retry-After"] = str(retry_after)
                return resp

            code = request.form.get("code", "").strip()
            if deck.mfa_store.verify_and_record(pending_uid, code):
                deck._rate_limiter.record_success(ip, f"mfa:{pending_uid}")
                dest_raw = str(session.pop(MFA_PENDING_NEXT_KEY, ""))
                pending_sso = session.pop(MFA_PENDING_SSO_KEY, None)
                session.pop(MFA_PENDING_USER_KEY, None)
                session.pop(MFA_PENDING_AT_KEY, None)
                target_user: DeckUser | None = None
                if isinstance(pending_sso, Mapping) and str(pending_sso.get("id")) == pending_uid:
                    target_user = DeckUser(
                        id=pending_uid,
                        username=str(pending_sso.get("username", pending_uid)),
                        display_name=str(pending_sso.get("display_name", "")),
                        email=str(pending_sso.get("email", "")),
                        roles=tuple(str(r) for r in pending_sso.get("roles", ())),
                        is_superuser=bool(pending_sso.get("is_superuser", False)),
                    )
                else:
                    target_user = deck.auth.get_user_by_id(pending_uid)
                if target_user is None:
                    return redirect(url_for(f"{bp_name}.login"))
                deck.auth.login_user(target_user)
                session[MFA_VERIFIED_KEY] = True
                _track_session(target_user)
                dest = dest_raw if is_safe_redirect_url(dest_raw) else url_for(f"{bp_name}.index")
                return redirect(dest)

            deck._rate_limiter.record_failure(ip, f"mfa:{pending_uid}")
            deck._emit_event("mfa.failed", payload={"user_id": pending_uid, "ip": ip})
            error_msg = "Invalid or already-used verification code."

        return render_template(
            "flask_deck/login_mfa.html",
            **deck._base_context(error_msg=error_msg),
        )

    @bp.route("/login/sso/<provider_name>")
    def sso_login(provider_name: str) -> Any:
        if not isinstance(deck.auth, OIDCAuthProvider):
            abort(404)
        if deck.auth.get_sso_provider(provider_name) is None:
            abort(404)
        next_url = request.args.get("next", "").strip()
        callback_uri = url_for(
            f"{bp_name}.sso_callback",
            provider_name=provider_name,
            _external=True,
        )
        auth_url = deck.auth.build_authorize_redirect(
            provider_name,
            redirect_uri=callback_uri,
            next_url=next_url if is_safe_redirect_url(next_url) else "",
        )
        return redirect(auth_url)

    @bp.route("/login/sso/<provider_name>/callback")
    def sso_callback(provider_name: str) -> Any:
        if not isinstance(deck.auth, OIDCAuthProvider):
            abort(404)
        if deck.auth.get_sso_provider(provider_name) is None:
            abort(404)
        callback_uri = url_for(
            f"{bp_name}.sso_callback",
            provider_name=provider_name,
            _external=True,
        )
        try:
            sso_user, next_url = deck.auth.complete_callback(
                provider_name,
                code=request.args.get("code", "").strip(),
                state=request.args.get("state", "").strip(),
                redirect_uri=callback_uri,
            )
        except (PermissionError, ValueError, OSError) as exc:
            deck._emit_event(
                "login.failed",
                payload={"provider": provider_name, "error": str(exc)},
            )
            return (
                render_template(
                    "flask_deck/login.html",
                    **deck._base_context(
                        next_url="",
                        error_msg=f"SSO sign-in failed: {exc}",
                        demo_credentials=deck._demo_credentials,
                    ),
                ),
                403,
            )
        dest = next_url if is_safe_redirect_url(next_url) else url_for(f"{bp_name}.index")
        if deck.mfa_store is not None:
            enrollment = deck.mfa_store.get(sso_user.id)
            if enrollment is not None and enrollment.enabled:
                session.clear()
                session[MFA_PENDING_USER_KEY] = sso_user.id
                session[MFA_PENDING_NEXT_KEY] = dest
                session[MFA_PENDING_AT_KEY] = int(time.time())
                session[MFA_PENDING_SSO_KEY] = {
                    "id": sso_user.id,
                    "username": sso_user.username,
                    "display_name": sso_user.display_name,
                    "email": sso_user.email,
                    "roles": list(sso_user.roles),
                    "is_superuser": sso_user.is_superuser,
                }
                rotate_csrf_token()
                return redirect(url_for(f"{bp_name}.login_mfa"))
        deck.auth.login_user(sso_user)
        _track_session(sso_user)
        return redirect(dest)

    @bp.route("/logout", methods=["POST"])
    def logout() -> Any:
        sid = session.get(DECK_SID_SESSION_KEY)
        if deck.session_store is not None and isinstance(sid, str) and sid:
            deck.session_store.revoke(sid)
        deck.auth.logout_user()
        if deck.auth.supports_login_form:
            return redirect(url_for(f"{bp_name}.login"))
        return redirect(url_for(f"{bp_name}.index"))

    @bp.route("/_security/mfa", methods=["GET", "POST"])
    def security_mfa() -> Any:
        if deck.mfa_store is None:
            abort(404)
        if getattr(g, "_deck_real_user", None) is not None:
            raise PermissionDeniedError(
                "MFA settings cannot be modified while impersonating another user."
            )
        user = deck._current_user()
        if user is None:
            abort(403)

        enrollment = deck.mfa_store.get(user.id)
        recovery_once: list[str] = []
        error_msg = ""
        mfa_required_for_user = bool(
            deck.config.require_mfa_for_superusers and user.is_superuser
        )

        if request.method == "POST":
            act = request.form.get("action", "").strip()
            if act == "disable":
                if mfa_required_for_user:
                    error_msg = "MFA cannot be disabled while superuser MFA enforcement is active."
                elif enrollment is not None and enrollment.enabled:
                    verify_code = request.form.get("code", "").strip()
                    if not verify_code or not deck.mfa_store.verify_and_record(user.id, verify_code):
                        error_msg = "Enter a valid current 6-digit TOTP or recovery code to disable 2FA."
                    else:
                        deck.mfa_store.delete(user.id)
                        session.pop(MFA_SETUP_SECRET_KEY, None)
                        session.pop(MFA_VERIFIED_KEY, None)
                        if deck.session_store is not None:
                            deck.session_store.revoke_others(
                                user.id,
                                keep_session_id=session.get(DECK_SID_SESSION_KEY),
                            )
                        enrollment = None
                        if deck.audit_store is not None and deck.config.auto_audit:
                            deck.audit_store.record(
                                make_audit_entry(
                                    actor_id=user.id,
                                    actor_name=user.label,
                                    actor_ip=_client_ip(),
                                    action="mfa_disabled",
                                    model_slug="_auth",
                                    model_label="MFA Security",
                                    record_pk=user.id,
                                    record_repr=user.label,
                                )
                            )
                        deck._emit_event("mfa.disabled", record_pk=user.id)
                        flash("Two-factor authentication disabled.", "warn")
            elif act == "enable":
                secret = str(session.get(MFA_SETUP_SECRET_KEY, ""))
                code = request.form.get("code", "").strip()
                if not secret:
                    error_msg = "Setup session expired. Refresh to generate a new secret."
                else:
                    step = verify_totp(secret, code)
                    if step is None:
                        error_msg = "Invalid 6-digit code. Check your authenticator clock and retry."
                    else:
                        plain_codes, hashed_codes = generate_recovery_codes(8)
                        enrollment = MFAEnrollment(
                            user_id=user.id,
                            secret=secret,
                            enabled=True,
                            last_step=step,
                            recovery_hashes=hashed_codes,
                            created_at=datetime.now(timezone.utc),
                        )
                        deck.mfa_store.save(enrollment)
                        session.pop(MFA_SETUP_SECRET_KEY, None)
                        session[MFA_VERIFIED_KEY] = True
                        if deck.session_store is not None:
                            deck.session_store.revoke_others(
                                user.id,
                                keep_session_id=session.get(DECK_SID_SESSION_KEY),
                            )
                        recovery_once = plain_codes
                        if deck.audit_store is not None and deck.config.auto_audit:
                            deck.audit_store.record(
                                make_audit_entry(
                                    actor_id=user.id,
                                    actor_name=user.label,
                                    actor_ip=_client_ip(),
                                    action="mfa_enabled",
                                    model_slug="_auth",
                                    model_label="MFA Security",
                                    record_pk=user.id,
                                    record_repr=user.label,
                                )
                            )
                        deck._emit_event("mfa.enabled", record_pk=user.id)
                        flash("Two-factor authentication enabled. Save your recovery codes now.", "ok")

        setup_secret = ""
        qr_svg = Markup("")
        otpauth_uri = ""
        if enrollment is None or not enrollment.enabled:
            setup_secret = str(session.get(MFA_SETUP_SECRET_KEY, ""))
            if not setup_secret:
                setup_secret = generate_totp_secret()
                session[MFA_SETUP_SECRET_KEY] = setup_secret
            otpauth_uri = build_otpauth_uri(
                secret=setup_secret,
                account_name=user.email or user.username,
                issuer=deck.config.title,
            )
            try:
                qr_svg = render_qr_svg(otpauth_uri, pixel_size=184)
            except ValueError:
                qr_svg = Markup(
                    '<div class="dk-chart-empty">Enter the manual Base32 secret below in your authenticator app.</div>'
                )

        return render_template(
            "flask_deck/mfa_setup.html",
            **deck._base_context(
                page_title="Two-Factor Authentication (TOTP)",
                active_nav="_mfa",
                enrollment=enrollment,
                mfa_required_for_user=mfa_required_for_user,
                setup_secret=setup_secret,
                otpauth_uri=otpauth_uri,
                qr_svg=qr_svg,
                recovery_once=recovery_once,
                error_msg=error_msg,
            ),
        )

    @bp.route("/_security/sessions")
    def security_sessions() -> Any:
        if deck.session_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            abort(403)
        can_view_all = bool(user.is_superuser)
        scope = request.args.get("scope", "mine").strip() if can_view_all else "mine"
        records = deck.session_store.list_sessions(
            user_id=None if (can_view_all and scope == "all") else user.id,
            limit=200,
        )
        return render_template(
            "flask_deck/sessions.html",
            **deck._base_context(
                page_title="Active Sessions",
                active_nav="_sessions",
                sessions_list=records,
                current_sid=str(session.get(DECK_SID_SESSION_KEY, "")),
                scope=scope,
                can_view_all=can_view_all,
            ),
        )

    @bp.route("/_security/sessions/<sid>/revoke", methods=["POST"])
    def security_session_revoke(sid: str) -> Any:
        if deck.session_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            abort(403)
        actor_scope = None if user.is_superuser else user.id
        ok = deck.session_store.revoke(sid, actor_id=actor_scope)
        if ok:
            if deck.audit_store is not None and deck.config.auto_audit:
                deck.audit_store.record(
                    make_audit_entry(
                        actor_id=user.id,
                        actor_name=user.label,
                        actor_ip=_client_ip(),
                        action="session.revoked",
                        model_slug="_auth",
                        model_label="Session",
                        record_pk=sid,
                        record_repr=sid,
                    )
                )
            deck._emit_event("session.revoked", record_pk=sid)
            flash("Session revoked.", "ok")
        else:
            flash("Session not found or already revoked.", "warn")
        scope = request.form.get("scope", "mine").strip()
        return redirect(url_for(f"{bp_name}.security_sessions", scope=scope))

    @bp.route("/_security/sessions/revoke-others", methods=["POST"])
    def security_sessions_revoke_others() -> Any:
        if deck.session_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            abort(403)
        current_sid = session.get(DECK_SID_SESSION_KEY)
        count = deck.session_store.revoke_others(
            user.id,
            keep_session_id=str(current_sid) if isinstance(current_sid, str) else None,
        )
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=user.id,
                    actor_name=user.label,
                    actor_ip=_client_ip(),
                    action="session.revoked_others",
                    model_slug="_auth",
                    model_label="Session",
                    record_pk=user.id,
                    record_repr=f"{count} sessions",
                    metadata={"revoked_count": count},
                )
            )
        flash(f"Revoked {count} other active session(s).", "ok")
        return redirect(url_for(f"{bp_name}.security_sessions"))

    @bp.route("/_security/passkeys")
    def security_passkeys() -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            abort(403)
        creds = deck.passkey_store.list_for_user(user.id)
        return render_template(
            "flask_deck/passkeys.html",
            **deck._base_context(
                page_title="Passkeys (WebAuthn)",
                active_nav="_passkeys",
                credentials=creds,
                webauthn_available=is_webauthn_available(),
            ),
        )

    @bp.route("/_security/passkeys/register/options", methods=["POST"])
    def passkey_register_options() -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            return jsonify({"error": "Authentication required."}), 401
        rp_id, _ = _rp_id_and_origin()
        existing = deck.passkey_store.list_for_user(user.id)
        try:
            opts, challenge = begin_passkey_registration(
                rp_id=rp_id,
                rp_name=deck.config.title,
                user_id=user.id,
                user_name=user.username,
                exclude_credentials=existing,
            )
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 501
        session[PASSKEY_REG_CHALLENGE_KEY] = challenge
        return jsonify({"options": opts})

    @bp.route("/_security/passkeys/register/verify", methods=["POST"])
    def passkey_register_verify() -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            return jsonify({"error": "Authentication required."}), 401
        challenge = session.pop(PASSKEY_REG_CHALLENGE_KEY, None)
        if not isinstance(challenge, str) or not challenge:
            return jsonify({"error": "Missing or expired registration challenge."}), 400
        payload = request.get_json(silent=True) or {}
        cred_json = payload.get("credential")
        if cred_json is None:
            return jsonify({"error": "Missing credential payload."}), 400
        label = str(payload.get("label") or "Passkey").strip()[:120] or "Passkey"
        rp_id, origin = _rp_id_and_origin()
        try:
            cred = complete_passkey_registration(
                credential_json=cred_json,
                expected_challenge_b64=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                user_id=user.id,
                label=label,
            )
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 501
        except Exception as exc:
            return jsonify({"error": f"Passkey verification failed: {exc}"}), 400
        deck.passkey_store.add(cred)
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=user.id,
                    actor_name=user.label,
                    actor_ip=_client_ip(),
                    action="passkey.registered",
                    model_slug="_auth",
                    model_label="Passkey",
                    record_pk=cred.credential_id,
                    record_repr=cred.label,
                )
            )
        deck._emit_event("passkey.registered", record_pk=cred.credential_id)
        return jsonify({"ok": True, "credential_id": cred.credential_id, "label": cred.label})

    @bp.route("/_security/passkeys/<path:credential_id>/delete", methods=["POST"])
    def passkey_delete(credential_id: str) -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        user = deck._current_user()
        if user is None:
            abort(403)
        if deck.passkey_store.delete(credential_id, user_id=user.id):
            if deck.audit_store is not None and deck.config.auto_audit:
                deck.audit_store.record(
                    make_audit_entry(
                        actor_id=user.id,
                        actor_name=user.label,
                        actor_ip=_client_ip(),
                        action="passkey.deleted",
                        model_slug="_auth",
                        model_label="Passkey",
                        record_pk=credential_id,
                        record_repr=credential_id,
                    )
                )
            flash("Passkey removed.", "ok")
        else:
            flash("Passkey not found.", "warn")
        return redirect(url_for(f"{bp_name}.security_passkeys"))

    @bp.route("/login/passkey/options", methods=["POST"])
    def passkey_login_options() -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        rp_id, _ = _rp_id_and_origin()
        try:
            opts, challenge = begin_passkey_authentication(rp_id=rp_id)
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 501
        session[PASSKEY_AUTH_CHALLENGE_KEY] = challenge
        return jsonify({"options": opts})

    @bp.route("/login/passkey/verify", methods=["POST"])
    def passkey_login_verify() -> Any:
        if deck.passkey_store is None or not deck.auth.supports_login_form:
            abort(404)
        challenge = session.pop(PASSKEY_AUTH_CHALLENGE_KEY, None)
        if not isinstance(challenge, str) or not challenge:
            return jsonify({"error": "Missing or expired passkey challenge."}), 400
        payload = request.get_json(silent=True) or {}
        cred_json = payload.get("credential")
        if not isinstance(cred_json, Mapping):
            return jsonify({"error": "Missing credential payload."}), 400
        cred_id = str(cred_json.get("id") or cred_json.get("rawId") or "").strip()
        stored = deck.passkey_store.get(cred_id) if cred_id else None
        if stored is None:
            return jsonify({"error": "Unknown passkey credential."}), 404
        rp_id, origin = _rp_id_and_origin()
        try:
            new_count = complete_passkey_authentication(
                credential_json=cred_json,
                expected_challenge_b64=challenge,
                expected_origin=origin,
                expected_rp_id=rp_id,
                stored=stored,
            )
        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 501
        except Exception as exc:
            deck._emit_event("login.failed", payload={"method": "passkey", "error": str(exc)})
            return jsonify({"error": f"Passkey sign-in failed: {exc}"}), 403
        target_user = deck.auth.get_user_by_id(stored.user_id)
        if target_user is None:
            return jsonify({"error": "Account no longer exists."}), 403
        deck.passkey_store.update_sign_count(stored.credential_id, new_count)
        deck.auth.login_user(target_user)
        session[MFA_VERIFIED_KEY] = True
        _track_session(target_user)
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=target_user.id,
                    actor_name=target_user.label,
                    actor_ip=_client_ip(),
                    action="login.passkey",
                    model_slug="_auth",
                    model_label="Passkey",
                    record_pk=stored.credential_id,
                    record_repr=stored.label,
                )
            )
        next_raw = str(payload.get("next") or "")
        dest = next_raw if is_safe_redirect_url(next_raw) else url_for(f"{bp_name}.index")
        return jsonify({"ok": True, "redirect": dest})

    @bp.route("/_impersonate/start", methods=["POST"])
    def impersonate_start() -> Any:
        if not deck.config.enable_impersonation:
            abort(404)
        real = deck._real_user()
        if real is None or not real.is_superuser:
            raise PermissionDeniedError("Only superusers may impersonate accounts.")
        if not deck.auth.has_permission(real, "impersonate:use"):
            raise PermissionDeniedError("Missing permission: impersonate:use")
        target_id = request.form.get("target_user_id", "").strip()
        allowed = {u.id: u for u in deck.auth.get_impersonatable_users(real)}
        target = allowed.get(target_id)
        if target is None or target.id == real.id or target.is_superuser:
            flash("Cannot impersonate this account (superusers cannot be impersonated).", "danger")
            return redirect(url_for(f"{bp_name}.index"))
        session[IMPERSONATOR_USER_KEY] = real.id
        session[IMPERSONATED_USER_KEY] = target.id
        session[IMPERSONATE_RO_KEY] = deck.config.impersonate_read_only
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=real.id,
                    actor_name=real.label,
                    actor_ip=_client_ip(),
                    action="impersonate_start",
                    model_slug="_auth",
                    model_label="Impersonation",
                    record_pk=target.id,
                    record_repr=target.label,
                    metadata={"read_only": deck.config.impersonate_read_only},
                )
            )
        flash(f"Now viewing as {target.label} ({', '.join(target.roles)}).", "warn")
        return redirect(url_for(f"{bp_name}.index"))

    @bp.route("/_impersonate/stop", methods=["POST"])
    def impersonate_stop() -> Any:
        real = getattr(g, "_deck_real_user", None)
        imp_id = session.pop(IMPERSONATED_USER_KEY, None)
        session.pop(IMPERSONATOR_USER_KEY, None)
        session.pop(IMPERSONATE_RO_KEY, None)
        if real is not None and imp_id and deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=real.id,
                    actor_name=real.label,
                    actor_ip=_client_ip(),
                    action="impersonate_stop",
                    model_slug="_auth",
                    model_label="Impersonation",
                    record_pk=str(imp_id),
                    record_repr=str(imp_id),
                )
            )
        flash("Exited impersonation mode.", "ok")
        return redirect(url_for(f"{bp_name}.index"))

    @bp.route("/_demo/switch-role", methods=["POST"])
    def demo_switch_role() -> Any:
        if (
            not deck.config.demo_role_switcher
            or deck.config.environment == "production"
            or not isinstance(deck.auth, RBACAuthProvider)
        ):
            abort(404)
        target_id = request.form.get("account_id", "").strip()
        target_user = deck.auth.get_account_by_id(target_id)
        if target_user is None:
            abort(404)
        deck.auth.login_user(target_user)
        _track_session(target_user)
        flash(
            f"Switched demo session role to {target_user.label} ({', '.join(target_user.roles)}).",
            "ok",
        )
        nxt = request.form.get("next", "").strip()
        dest = nxt if is_safe_redirect_url(nxt) else url_for(f"{bp_name}.index")
        return redirect(dest)

    @bp.route("/_security/api-keys")
    def security_api_keys() -> str:
        if deck.api_key_store is None:
            abort(404)
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "api_keys:manage")
        ):
            raise PermissionDeniedError("Missing permission: api_keys:manage")
        keys = deck.api_key_store.list_keys(
            owner_id=None if user.is_superuser else user.id,
            limit=100,
        )
        new_plaintext = session.pop("_deck_new_api_key", None)
        available_roles = [r.name for r in deck.auth.get_roles()] if user.is_superuser else list(user.roles)
        return render_template(
            "flask_deck/api_keys.html",
            **deck._base_context(
                page_title="API Keys",
                active_nav="_api_keys",
                keys=keys,
                new_plaintext=new_plaintext,
                available_roles=available_roles,
                can_grant_superuser=user.is_superuser,
            ),
        )

    @bp.route("/_security/api-keys/create", methods=["POST"])
    def security_api_keys_create() -> Any:
        if deck.api_key_store is None:
            abort(404)
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "api_keys:manage")
        ):
            raise PermissionDeniedError("Missing permission: api_keys:manage")

        name = request.form.get("name", "").strip()[:120] or "Integration Key"
        raw_scopes = request.form.get("scopes", "*:view")
        scopes = [s.strip() for s in raw_scopes.replace("\n", ",").split(",") if s.strip()] or [
            "*:view"
        ]
        raw_roles = request.form.get("roles", "")
        requested_roles = [r.strip() for r in raw_roles.split(",") if r.strip()]
        if user.is_superuser:
            roles = requested_roles or list(user.roles) or ["viewer"]
            grant_super = request.form.get("is_superuser") in {"1", "true", "on"}
        else:
            allowed_role_set = set(user.roles)
            roles = [r for r in requested_roles if r in allowed_role_set] or list(user.roles) or ["viewer"]
            grant_super = False

        raw_ips = request.form.get("allowed_ips", "")
        allowed_ips = [ip.strip() for ip in raw_ips.replace("\n", ",").split(",") if ip.strip()]
        ttl_raw = request.form.get("ttl_days", "").strip()
        try:
            ttl_days = int(ttl_raw) if ttl_raw else None
        except ValueError:
            ttl_days = None

        plaintext, rec = build_api_key_record(
            name=name,
            owner_id=user.id,
            owner_name=user.label,
            scopes=scopes,
            roles=roles,
            allowed_ips=allowed_ips,
            is_superuser=grant_super,
            ttl_days=ttl_days,
        )
        stored = deck.api_key_store.create(rec)
        session["_deck_new_api_key"] = plaintext
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=user.id,
                    actor_name=user.label,
                    actor_ip=_client_ip(),
                    action="api_key.created",
                    model_slug="_security",
                    model_label="API Key",
                    record_pk=stored.id,
                    record_repr=f"{stored.name} ({stored.prefix}...)",
                    metadata={"scopes": list(stored.scopes), "roles": list(stored.roles)},
                )
            )
        flash(f"Created API key '{stored.name}'. Copy the secret now; it will not be shown again.", "ok")
        return redirect(url_for(f"{bp_name}.security_api_keys"))

    @bp.route("/_security/api-keys/<key_id>/revoke", methods=["POST"])
    def security_api_keys_revoke(key_id: str) -> Any:
        if deck.api_key_store is None:
            abort(404)
        user = deck._current_user()
        if user is None or not (
            user.is_superuser or deck.auth.has_permission(user, "api_keys:manage")
        ):
            raise PermissionDeniedError("Missing permission: api_keys:manage")
        ok = deck.api_key_store.revoke(
            key_id, owner_id=None if user.is_superuser else user.id
        )
        if not ok:
            flash("API key not found, already revoked, or not owned by you.", "warn")
            return redirect(url_for(f"{bp_name}.security_api_keys"))
        if deck.audit_store is not None and deck.config.auto_audit:
            deck.audit_store.record(
                make_audit_entry(
                    actor_id=user.id,
                    actor_name=user.label,
                    actor_ip=_client_ip(),
                    action="api_key.revoked",
                    model_slug="_security",
                    model_label="API Key",
                    record_pk=key_id,
                    record_repr=key_id,
                )
            )
        flash("API key revoked immediately.", "ok")
        return redirect(url_for(f"{bp_name}.security_api_keys"))
