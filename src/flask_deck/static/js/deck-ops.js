/* Flask-Deck — Operations: SSE Jobs + Live Logs, SQL Console & Schema */
(function () {
  "use strict";
  const D = window.__deck;
  if (!D) return;

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    const sqlPreset = t.closest("[data-deck-sql-preset]");
    if (sqlPreset) {
      const ed = document.getElementById("dk-sql-editor");
      if (ed) { ed.value = sqlPreset.getAttribute("data-deck-sql-preset") || ""; ed.focus(); }
      return;
    }
    const zBtn = t.closest("[data-erd-zoom]");
    const svg = document.querySelector("[data-erd-svg]");
    if (zBtn && svg) {
      const mode = zBtn.getAttribute("data-erd-zoom");
      const base = (svg.getAttribute("data-base-vb") || "").split(/\s+/).map(Number);
      if (base.length === 4 && base[2] > 0) {
        const prev = Number(svg.getAttribute("data-zoom-scale") || "1");
        const next = mode === "in" ? Math.min(2.5, prev * 1.25) : (mode === "out" ? Math.max(0.5, prev * 0.8) : 1);
        svg.setAttribute("data-zoom-scale", String(next));
        svg.setAttribute("viewBox", "0 0 " + Math.round(base[2] / next) + " " + Math.round(base[3] / next));
      }
    }
  });

  const activeStreams = [];
  const activePollers = [];
  document.querySelectorAll("[data-deck-job-stream]").forEach((row) => {
    const streamUrl = row.getAttribute("data-deck-job-stream");
    const pollUrl = row.getAttribute("data-deck-job-poll");
    if (!streamUrl && !pollUrl) return;
    let done = false;
    function applyJob(data) {
      if (!data || !data.status) return;
      const st = row.querySelector("[data-job-status]");
      const bar = row.querySelector("[data-job-bar]");
      const pct = row.querySelector("[data-job-pct]");
      const msg = row.querySelector("[data-job-msg]");
      const logsPre = row.querySelector("[data-job-logs]");
      const logsSummary = row.querySelector("[data-job-logs-summary]");
      const logsWrap = logsPre ? logsPre.closest(".dk-job-logs") : null;
      if (st) {
        const tone = data.status === "succeeded" ? "ok" : (data.status === "failed" ? "danger" : (data.status === "running" || data.status === "queued" ? "warn" : "neutral"));
        st.className = "dk-badge dk-badge-" + tone + " dk-mono";
        const dot = document.createElement("span");
        dot.className = "dk-dot";
        st.replaceChildren(dot, document.createTextNode(String(data.status)));
      }
      if (bar) {
        bar.setAttribute("width", String(data.progress || 0));
        bar.setAttribute("class", data.status === "failed" ? "dk-prog-fill-danger" : "dk-prog-fill-ok");
      }
      if (pct) pct.textContent = (data.progress || 0) + "%";
      if (msg && (data.error || data.message)) {
        const target = msg.firstElementChild || msg;
        target.textContent = data.error || data.message;
      }
      if (Array.isArray(data.logs) && data.logs.length && logsPre) {
        if (logsWrap) logsWrap.hidden = false;
        if (logsSummary) logsSummary.textContent = "Logs (" + data.logs.length + ")";
        logsPre.textContent = data.logs.join("\n");
        logsPre.scrollTop = logsPre.scrollHeight;
      }
      if (data.status === "succeeded" || data.status === "failed" || data.status === "cancelled") {
        done = true;
        const cancelForm = row.querySelector('form[action$="/cancel"]');
        if (cancelForm) cancelForm.hidden = true;
        if (data.artifact_filename) window.location.reload();
      }
    }
    function startPoll() {
      if (done || !pollUrl) return;
      const tid = window.setInterval(() => {
        if (done) { window.clearInterval(tid); return; }
        fetch(pollUrl, { headers: { Accept: "application/json" } })
          .then((r) => (r.ok ? r.json() : null))
          .then((d) => { if (d) applyJob(d); if (done) window.clearInterval(tid); })
          .catch(() => {});
      }, 2000);
      activePollers.push(tid);
    }
    if (streamUrl && typeof EventSource !== "undefined") {
      let lastId = "";
      const es = new EventSource(streamUrl);
      activeStreams.push(es);
      es.onmessage = (ev) => {
        if (ev.lastEventId) lastId = ev.lastEventId;
        let data = null;
        try { data = JSON.parse(ev.data); } catch (_) { return; }
        applyJob(data);
        if (done) es.close();
      };
      es.onerror = () => {
        es.close();
        if (!done) {
          row.setAttribute("data-last-event-id", lastId);
          startPoll();
        }
      };
    } else {
      startPoll();
    }
  });
  window.addEventListener("pagehide", () => {
    activeStreams.forEach((es) => { try { es.close(); } catch (_) {} });
    activePollers.forEach((tid) => window.clearInterval(tid));
  });

  function b64d(s) {
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }
  function b64e(buf) {
    const arr = new Uint8Array(buf);
    let bin = "";
    arr.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function csrfHdr() {
    const m = document.querySelector('meta[name="deck-csrf"]');
    return { "Content-Type": "application/json", "X-Deck-CSRFToken": m ? m.content : "" };
  }
  const pkReg = document.querySelector("[data-deck-passkey-register]");
  if (pkReg && navigator.credentials) {
    pkReg.addEventListener("click", async () => {
      const st = document.querySelector("[data-passkey-status]");
      const inp = document.getElementById(pkReg.getAttribute("data-label-input") || "");
      const label = inp ? inp.value.trim() : "Passkey";
      try {
        const o = await fetch(pkReg.getAttribute("data-options-url"), { method: "POST", headers: csrfHdr(), body: "{}" }).then((r) => r.json());
        if (o.error || !o.options) throw new Error(o.error || "Failed");
        const opts = o.options;
        opts.challenge = b64d(opts.challenge);
        opts.user.id = b64d(opts.user.id);
        if (Array.isArray(opts.excludeCredentials)) opts.excludeCredentials.forEach((c) => { c.id = b64d(c.id); });
        const cred = await navigator.credentials.create({ publicKey: opts });
        const res = {
          id: cred.id, rawId: b64e(cred.rawId), type: cred.type,
          response: { attestationObject: b64e(cred.response.attestationObject), clientDataJSON: b64e(cred.response.clientDataJSON) }
        };
        const v = await fetch(pkReg.getAttribute("data-verify-url"), { method: "POST", headers: csrfHdr(), body: JSON.stringify({ credential: res, label }) }).then((r) => r.json());
        if (!v.ok) throw new Error(v.error || "Verify failed");
        window.location.reload();
      } catch (err) { if (st) st.textContent = String(err.message || err); }
    });
  }
  const pkLog = document.querySelector("[data-deck-passkey-login]");
  if (pkLog && navigator.credentials) {
    pkLog.addEventListener("click", async () => {
      try {
        const o = await fetch(pkLog.getAttribute("data-options-url"), { method: "POST", headers: csrfHdr(), body: "{}" }).then((r) => r.json());
        if (o.error || !o.options) throw new Error(o.error || "Failed");
        const opts = o.options;
        opts.challenge = b64d(opts.challenge);
        if (Array.isArray(opts.allowCredentials)) opts.allowCredentials.forEach((c) => { c.id = b64d(c.id); });
        const cred = await navigator.credentials.get({ publicKey: opts });
        const res = {
          id: cred.id, rawId: b64e(cred.rawId), type: cred.type,
          response: { authenticatorData: b64e(cred.response.authenticatorData), clientDataJSON: b64e(cred.response.clientDataJSON), signature: b64e(cred.response.signature), userHandle: cred.response.userHandle ? b64e(cred.response.userHandle) : null }
        };
        const v = await fetch(pkLog.getAttribute("data-verify-url"), { method: "POST", headers: csrfHdr(), body: JSON.stringify({ credential: res, next: pkLog.getAttribute("data-next-url") || "" }) }).then((r) => r.json());
        if (v.ok && v.redirect) window.location.assign(v.redirect);
      } catch (err) { if (D.toast) D.toast(String(err.message || err), "danger"); }
    });
  }
})();
