/* Flask-Deck — Zero-Dependency, Strict-CSP Core Runtime */
(function () {
  "use strict";

  const root = document.documentElement;
  const metaVal = (n) => { const m = document.querySelector('meta[name="' + n + '"]'); return m ? m.content : ""; };
  const CSRF = metaVal("deck-csrf");
  const SEARCH_URL = metaVal("deck-search-url");
  const NOTIF_URL = metaVal("deck-notif-url");

  function showToast(msg, tone) {
    const host = document.getElementById("dk-toasts");
    if (!host) return;
    const el = document.createElement("div");
    el.className = "dk-toast" + (tone ? " dk-toast-" + tone : "");
    const span = document.createElement("span");
    span.textContent = String(msg);
    el.appendChild(span);
    host.appendChild(el);
    window.setTimeout(() => { el.remove(); }, 3400);
  }

  function toggleTheme() {
    const cur = root.getAttribute("data-theme") === "light" ? "light" : "dark";
    const next = cur === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("flask_deck_theme", next); } catch (_) {}
    showToast("Theme: " + (next === "dark" ? "Carbon Dark" : "Swiss Light"));
  }

  function toggleDensity() {
    const isCompact = root.getAttribute("data-density") === "compact";
    if (isCompact) root.removeAttribute("data-density");
    else root.setAttribute("data-density", "compact");
    try { localStorage.setItem("flask_deck_density", isCompact ? "comfortable" : "compact"); } catch (_) {}
    showToast("Density: " + (isCompact ? "Comfortable" : "Compact"));
  }

  function toggleRail() {
    const shell = document.getElementById("dk-shell");
    if (!shell) return;
    shell.classList.toggle(window.innerWidth <= 768 ? "dk-mobile-open" : "dk-rail-collapsed");
  }

  const railFilter = document.getElementById("dk-rail-filter");
  if (railFilter) {
    railFilter.addEventListener("input", () => {
      const q = railFilter.value.trim().toLowerCase();
      document.querySelectorAll("[data-rail-group]").forEach((grp) => {
        let visible = 0;
        grp.querySelectorAll("[data-rail-item]").forEach((item) => {
          const match = !q || (item.getAttribute("data-rail-item") || "").includes(q);
          item.hidden = !match;
          if (match) visible += 1;
        });
        grp.hidden = visible === 0;
      });
    });
  }

  /* ---------- ⌘K Command Palette ---------- */
  const cmdkBackdrop = document.getElementById("dk-cmdk-backdrop");
  const cmdkInput = document.getElementById("dk-cmdk-input");
  const cmdkList = document.getElementById("dk-cmdk-list");
  let cmdkActiveIdx = 0;
  let cmdkTimer = null;
  let cmdkAbort = null;

  function staticCommands() {
    const cmds = [
      { kind: "action", title: "Toggle Carbon Dark / Swiss Light", subtitle: "Switch workbench color scheme", badge: "Theme", run: toggleTheme },
      { kind: "action", title: "Toggle Compact / Comfortable Density", subtitle: "Adjust table row padding", badge: "Density", run: toggleDensity },
    ];
    document.querySelectorAll("[data-deck-quick-nav]").forEach((a) => {
      cmds.push({
        kind: "nav",
        title: a.getAttribute("data-title") || a.textContent.trim(),
        subtitle: a.getAttribute("data-subtitle") || "Navigate",
        badge: "View",
        url: a.getAttribute("href"),
      });
    });
    return cmds;
  }

  function renderCmdkItems(items) {
    if (!cmdkList) return;
    cmdkList.replaceChildren();
    cmdkActiveIdx = 0;
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "dk-chart-empty";
      empty.textContent = "No matching models, records, or commands.";
      cmdkList.appendChild(empty);
      return;
    }
    items.forEach((item, idx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "dk-cmdk-item" + (idx === 0 ? " is-active" : "");
      const left = document.createElement("div");
      const title = document.createElement("div");
      title.textContent = item.title;
      const sub = document.createElement("div");
      sub.className = "dk-subtle";
      sub.textContent = item.subtitle || "";
      left.appendChild(title);
      left.appendChild(sub);
      const badge = document.createElement("span");
      badge.className = "dk-badge dk-badge-neutral dk-mono";
      badge.textContent = item.badge || "";
      btn.appendChild(left);
      btn.appendChild(badge);
      btn.addEventListener("click", () => {
        closeCmdk();
        if (typeof item.run === "function") item.run();
        else if (item.url) window.location.assign(item.url);
      });
      cmdkList.appendChild(btn);
    });
  }

  function runCmdkSearch(query) {
    const q = (query || "").trim();
    const locals = staticCommands().filter((c) => !q || c.title.toLowerCase().includes(q.toLowerCase()));
    if (!SEARCH_URL) { renderCmdkItems(locals); return; }
    if (cmdkAbort) cmdkAbort.abort();
    cmdkAbort = new AbortController();
    fetch(SEARCH_URL + "?q=" + encodeURIComponent(q), { headers: { Accept: "application/json" }, signal: cmdkAbort.signal })
      .then((r) => (r.ok ? r.json() : { results: [] }))
      .then((data) => renderCmdkItems((Array.isArray(data.results) ? data.results : []).concat(locals)))
      .catch(() => {});
  }

  function openCmdk() {
    if (!cmdkBackdrop || !cmdkInput) return;
    cmdkBackdrop.hidden = false;
    cmdkInput.value = "";
    cmdkInput.focus();
    runCmdkSearch("");
  }
  function closeCmdk() { if (cmdkBackdrop) cmdkBackdrop.hidden = true; }

  if (cmdkInput) {
    cmdkInput.addEventListener("input", () => {
      window.clearTimeout(cmdkTimer);
      cmdkTimer = window.setTimeout(() => runCmdkSearch(cmdkInput.value), 120);
    });
    cmdkInput.addEventListener("keydown", (e) => {
      if (!cmdkList) return;
      const btns = Array.from(cmdkList.querySelectorAll(".dk-cmdk-item"));
      if (!btns.length) return;
      if (e.key === "ArrowDown") { e.preventDefault(); cmdkActiveIdx = (cmdkActiveIdx + 1) % btns.length; }
      else if (e.key === "ArrowUp") { e.preventDefault(); cmdkActiveIdx = (cmdkActiveIdx - 1 + btns.length) % btns.length; }
      else if (e.key === "Enter") { e.preventDefault(); btns[cmdkActiveIdx]?.click(); return; }
      else return;
      btns.forEach((b, i) => b.classList.toggle("is-active", i === cmdkActiveIdx));
      btns[cmdkActiveIdx]?.scrollIntoView({ block: "nearest" });
    });
  }

  /* ---------- Drawer, Popovers, Confirm & Lightbox ---------- */
  const drawerBackdrop = document.getElementById("dk-drawer-backdrop");
  const drawerTitle = document.getElementById("dk-drawer-title");
  const drawerBody = document.getElementById("dk-drawer-body");
  const keysBackdrop = document.getElementById("dk-keys-backdrop");
  const confirmBackdrop = document.getElementById("dk-confirm-backdrop");
  const confirmTitle = document.getElementById("dk-confirm-title");
  const confirmMsg = document.getElementById("dk-confirm-msg");
  const confirmImpact = document.getElementById("dk-confirm-impact");
  const confirmFieldsHost = document.getElementById("dk-confirm-fields");
  const confirmPhraseWrap = document.getElementById("dk-confirm-phrase-wrap");
  const confirmPhraseLabel = document.getElementById("dk-confirm-phrase-label");
  const confirmInput = document.getElementById("dk-confirm-input");
  const confirmGo = document.getElementById("dk-confirm-go");
  const lbBackdrop = document.getElementById("dk-lightbox-backdrop");
  const lbImg = document.getElementById("dk-lightbox-img");
  const lbTitle = document.getElementById("dk-lightbox-title");
  const lbDl = document.getElementById("dk-lightbox-dl");
  let drawerAbort = null;
  let impactAbort = null;
  let pendingConfirmFn = null;
  let lbPrevFocus = null;

  function closePopovers(exceptEl) {
    document.querySelectorAll(".dk-popover").forEach((p) => { if (p !== exceptEl) p.hidden = true; });
  }

  function openDrawer(url, title) {
    if (!drawerBackdrop || !drawerBody) return;
    if (drawerAbort) drawerAbort.abort();
    drawerAbort = new AbortController();
    drawerBackdrop.hidden = false;
    if (drawerTitle) drawerTitle.textContent = title || "Record Inspector";
    drawerBody.textContent = "Loading…";
    fetch(url, { headers: { "X-Requested-With": "Flask-Deck" }, signal: drawerAbort.signal })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error("fail"))))
      .then((html) => {
        const doc = new DOMParser().parseFromString(html, "text/html");
        drawerBody.replaceChildren(...Array.from(doc.body.childNodes));
      })
      .catch((err) => {
        if (err && err.name === "AbortError") return;
        drawerBody.textContent = "Unable to load record details.";
      });
  }
  function closeDrawer() {
    if (drawerAbort) { drawerAbort.abort(); drawerAbort = null; }
    if (drawerBackdrop) drawerBackdrop.hidden = true;
  }
  function closeKeys() { if (keysBackdrop) keysBackdrop.hidden = true; }

  function toggleNotifs() {
    const pop = document.getElementById("dk-notif-pop");
    const list = document.getElementById("dk-notif-list");
    if (!pop || !list) return;
    closePopovers(pop);
    pop.hidden = !pop.hidden;
    if (pop.hidden || !NOTIF_URL) return;
    list.textContent = "Loading…";
    fetch(NOTIF_URL, { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : { items: [] }))
      .then((d) => {
        list.replaceChildren();
        const items = Array.isArray(d.items) ? d.items : [];
        if (!items.length) {
          const em = document.createElement("div");
          em.className = "dk-chart-empty";
          em.textContent = "No recent events.";
          list.appendChild(em);
          return;
        }
        items.forEach((it) => {
          const a = document.createElement("a");
          a.className = "dk-notif-item";
          a.href = it.url || "#";
          const top = document.createElement("div");
          top.textContent = "[" + it.action + "] " + it.title;
          const sub = document.createElement("div");
          sub.className = "dk-subtle dk-mono";
          sub.textContent = it.actor + " · " + it.time;
          a.appendChild(top);
          a.appendChild(sub);
          list.appendChild(a);
        });
      })
      .catch(() => { list.textContent = "Failed to load events."; });
  }

  function openConfirm(opts) {
    if (!confirmBackdrop) { opts.onConfirm("", {}); return; }
    if (confirmTitle) confirmTitle.textContent = opts.title || "Confirm Action";
    if (confirmMsg) confirmMsg.textContent = opts.message || "Proceed with this operation?";
    const fields = Array.isArray(opts.fields) ? opts.fields : [];
    const fieldInputs = {};
    if (confirmFieldsHost) {
      confirmFieldsHost.replaceChildren();
      confirmFieldsHost.hidden = fields.length === 0;
      fields.forEach((f) => {
        const wrap = document.createElement("div");
        wrap.className = "dk-field";
        const lbl = document.createElement("label");
        lbl.textContent = f.label + (f.required ? " *" : "");
        wrap.appendChild(lbl);
        let inp;
        if (f.type === "select") {
          inp = document.createElement("select");
          inp.className = "dk-select";
          (f.choices || []).forEach(([val, txt]) => {
            const o = document.createElement("option");
            o.value = val; o.textContent = txt;
            if (f.default === val) o.selected = true;
            inp.appendChild(o);
          });
        } else if (f.type === "textarea") {
          inp = document.createElement("textarea");
          inp.className = "dk-textarea";
          inp.value = f.default || ""; inp.placeholder = f.placeholder || "";
        } else if (f.type === "boolean") {
          inp = document.createElement("input");
          inp.type = "checkbox";
          inp.checked = f.default === true || f.default === "true" || f.default === "1";
        } else {
          inp = document.createElement("input");
          inp.type = f.type === "number" ? "number" : "text";
          inp.className = "dk-input";
          inp.value = f.default || ""; inp.placeholder = f.placeholder || "";
        }
        fieldInputs[f.name] = { el: inp, spec: f };
        wrap.appendChild(inp);
        confirmFieldsHost.appendChild(wrap);
      });
    }
    const phrase = opts.phrase || "";
    const demoLocked = Boolean(opts.demoLocked);
    const demoLockMsg = opts.demoLockMsg || "This action is disabled in public Demo Safe Mode.";
    let impactLoading = false;
    let impactBlocked = false;
    if (confirmGo) confirmGo.textContent = demoLocked ? "Disabled in Demo" : "Confirm";
    const syncConfirmBtn = () => {
      if (!confirmGo) return;
      const phraseMismatch = Boolean(phrase) && (!confirmInput || confirmInput.value.trim() !== phrase);
      confirmGo.disabled = demoLocked || impactLoading || impactBlocked || phraseMismatch;
    };
    const makeDemoLockNotice = () => {
      const box = document.createElement("div");
      box.className = "dk-alert dk-alert-warn";
      box.textContent = "DEMO LOCKED · " + demoLockMsg;
      return box;
    };
    if (confirmPhraseWrap && confirmInput && confirmPhraseLabel) {
      confirmPhraseWrap.hidden = !phrase;
      confirmInput.value = "";
      confirmPhraseLabel.textContent = phrase ? "Type " + phrase + " to confirm:" : "";
      confirmInput.oninput = syncConfirmBtn;
    }
    if (impactAbort) { impactAbort.abort(); impactAbort = null; }
    if (confirmImpact) {
      confirmImpact.replaceChildren();
      confirmImpact.hidden = !demoLocked;
      if (demoLocked) confirmImpact.appendChild(makeDemoLockNotice());
      if (opts.impactUrl && opts.impactBody) {
        impactLoading = true;
        confirmImpact.hidden = false;
        const ld = document.createElement("div");
        ld.className = "dk-subtle dk-mono";
        ld.textContent = "Analyzing dependent records…";
        confirmImpact.appendChild(ld);
        impactAbort = new AbortController();
        fetch(opts.impactUrl, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Deck-CSRFToken": CSRF,
            Accept: "application/json",
          },
          body: JSON.stringify(opts.impactBody),
          signal: impactAbort.signal,
        })
          .then((r) => (r.ok ? r.json() : Promise.reject(new Error("impact"))))
          .then((rep) => {
            confirmImpact.replaceChildren();
            if (demoLocked) confirmImpact.appendChild(makeDemoLockNotice());
            if (rep.is_soft_delete) {
              const info = document.createElement("div");
              info.className = "dk-impact-note dk-mono";
              info.textContent = "Soft delete — record moves to Trash safely without dropping DB rows.";
              confirmImpact.appendChild(info);
            }
            const items = Array.isArray(rep.items) ? rep.items : [];
            if (!items.length) {
              const ok = document.createElement("div");
              ok.className = "dk-subtle dk-mono";
              ok.textContent = "No dependent records affected.";
              confirmImpact.appendChild(ok);
            } else {
              const hdr = document.createElement("div");
              hdr.className = "dk-impact-head dk-mono";
              hdr.textContent = (rep.total_affected || 0) + " dependent record(s) across " + items.length + " relation(s):";
              confirmImpact.appendChild(hdr);
              items.forEach((it) => {
                const row = document.createElement("div");
                row.className = "dk-impact-row";
                const b = document.createElement("span");
                b.className = "dk-badge dk-badge-" + (it.action === "blocked" ? "danger" : (it.action === "cascade" ? "warn" : "info"));
                b.textContent = it.action === "blocked" ? "BLOCKED" : (it.action === "cascade" ? "CASCADE" : "SET NULL");
                const lbl = document.createElement("span");
                lbl.className = "dk-impact-label";
                lbl.textContent = it.model_label + " (" + it.fk_column + ") × " + it.count;
                row.appendChild(b);
                row.appendChild(lbl);
                const samples = Array.isArray(it.samples) ? it.samples : [];
                if (samples.length) {
                  const sWrap = document.createElement("div");
                  sWrap.className = "dk-impact-samples dk-mono";
                  samples.forEach((s) => {
                    if (s.url && (s.url.startsWith("/") || s.url.startsWith("https://") || s.url.startsWith("http://"))) {
                      const a = document.createElement("a");
                      a.href = s.url;
                      a.className = "dk-impact-sample-link";
                      a.textContent = s.label;
                      sWrap.appendChild(a);
                    } else {
                      const sp = document.createElement("span");
                      sp.className = "dk-impact-sample-link";
                      sp.textContent = s.label;
                      sWrap.appendChild(sp);
                    }
                  });
                  row.appendChild(sWrap);
                }
                confirmImpact.appendChild(row);
              });
              if (rep.truncated) {
                const tr = document.createElement("div");
                tr.className = "dk-subtle dk-mono";
                tr.textContent = "Tree truncated at limit.";
                confirmImpact.appendChild(tr);
              }
            }
            impactLoading = false;
            impactBlocked = rep.can_proceed === false;
            syncConfirmBtn();
          })
          .catch((err) => {
            if (err && err.name === "AbortError") return;
            confirmImpact.replaceChildren();
            if (demoLocked) confirmImpact.appendChild(makeDemoLockNotice());
            const warn = document.createElement("div");
            warn.className = "dk-subtle dk-mono";
            warn.textContent = "Unable to compute dependency preview.";
            confirmImpact.appendChild(warn);
            impactLoading = false;
            syncConfirmBtn();
          });
      }
    }
    syncConfirmBtn();
    pendingConfirmFn = () => {
      if (demoLocked) return;
      const extras = {};
      for (const [k, { el, spec }] of Object.entries(fieldInputs)) {
        if (spec.type === "boolean") { extras[k] = el.checked ? "true" : "false"; continue; }
        const v = String(el.value || "").trim();
        if (spec.required && !v) { showToast(spec.label + " is required", "danger"); el.focus(); return; }
        extras[k] = v;
      }
      const val = confirmInput ? confirmInput.value.trim() : "";
      closeConfirm();
      opts.onConfirm(val, extras);
    };
    confirmBackdrop.hidden = false;
    if (phrase && confirmInput) confirmInput.focus();
  }
  function closeConfirm() {
    if (impactAbort) { impactAbort.abort(); impactAbort = null; }
    if (confirmBackdrop) confirmBackdrop.hidden = true;
    pendingConfirmFn = null;
  }
  if (confirmGo) confirmGo.addEventListener("click", () => { if (typeof pendingConfirmFn === "function") pendingConfirmFn(); });

  if (lbImg) {
    lbImg.addEventListener("error", () => {
      if (lbBackdrop && !lbBackdrop.hidden) showToast("Unable to load image preview.", "danger");
    });
  }
  function openLightbox(url, title) {
    if (!lbBackdrop || !lbImg || !url) return;
    lbPrevFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    lbImg.src = url;
    lbImg.alt = title || "Preview";
    if (lbTitle) lbTitle.textContent = title || "Preview";
    if (lbDl) { lbDl.href = url; lbDl.setAttribute("download", title || "preview"); }
    lbBackdrop.hidden = false;
  }
  function closeLightbox() {
    if (!lbBackdrop || lbBackdrop.hidden) return;
    lbBackdrop.hidden = true;
    if (lbImg) lbImg.removeAttribute("src");
    if (lbPrevFocus) { try { lbPrevFocus.focus(); } catch (_) {} lbPrevFocus = null; }
  }

  function renderSafeMarkdown(text, host) {
    host.replaceChildren();
    const lines = String(text || "").split(/\r?\n/);
    let ul = null;
    const appendInline = (parent, str) => {
      const parts = str.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
      parts.forEach((p) => {
        if (!p) return;
        if (p.startsWith("`") && p.endsWith("`")) {
          const c = document.createElement("code"); c.className = "dk-code"; c.textContent = p.slice(1, -1); parent.appendChild(c);
        } else if (p.startsWith("**") && p.endsWith("**")) {
          const s = document.createElement("strong"); s.textContent = p.slice(2, -2); parent.appendChild(s);
        } else {
          parent.appendChild(document.createTextNode(p));
        }
      });
    };
    lines.forEach((line) => {
      const trimmed = line.trim();
      if (!trimmed) { ul = null; return; }
      if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        if (!ul) { ul = document.createElement("ul"); host.appendChild(ul); }
        const li = document.createElement("li"); appendInline(li, trimmed.slice(2)); ul.appendChild(li);
      } else {
        ul = null;
        if (trimmed.startsWith("### ")) { const h = document.createElement("h3"); h.textContent = trimmed.slice(4); host.appendChild(h); }
        else if (trimmed.startsWith("## ")) { const h = document.createElement("h2"); h.textContent = trimmed.slice(3); host.appendChild(h); }
        else if (trimmed.startsWith("# ")) { const h = document.createElement("h1"); h.textContent = trimmed.slice(2); host.appendChild(h); }
        else if (trimmed.startsWith("> ")) { const bq = document.createElement("blockquote"); appendInline(bq, trimmed.slice(2)); host.appendChild(bq); }
        else { const p = document.createElement("p"); appendInline(p, trimmed); host.appendChild(p); }
      }
    });
    if (!host.childNodes.length) {
      const em = document.createElement("span"); em.className = "dk-subtle"; em.textContent = "Nothing to preview."; host.appendChild(em);
    }
  }

  document.querySelectorAll("[data-deck-chart]").forEach((wrap) => {
    const tooltip = wrap.querySelector(".dk-chart-tooltip");
    const crosshair = wrap.querySelector(".dk-chart-crosshair");
    if (!tooltip) return;
    wrap.addEventListener("mouseover", (e) => {
      const target = e.target.closest("[data-label][data-value]");
      if (!target) return;
      const lbl = target.getAttribute("data-label") || "";
      const ser = target.getAttribute("data-series") || "";
      const val = target.getAttribute("data-value") || "";
      tooltip.textContent = (ser ? ser + " · " : "") + lbl + ": " + val;
      tooltip.hidden = false;
      const host = tooltip.offsetParent || wrap;
      const rect = host.getBoundingClientRect();
      const tRect = target.getBoundingClientRect();
      const tw = tooltip.offsetWidth || 140;
      tooltip.style.left = Math.max(4, Math.min(Math.max(4, rect.width - tw - 4), tRect.left - rect.left + 8)) + "px";
      tooltip.style.top = Math.max(4, tRect.top - rect.top - 28) + "px";
      if (crosshair && target.hasAttribute("data-x")) {
        const x = target.getAttribute("data-x");
        crosshair.setAttribute("x1", x);
        crosshair.setAttribute("x2", x);
        crosshair.hidden = false;
      }
    });
    wrap.addEventListener("mouseleave", () => { tooltip.hidden = true; if (crosshair) crosshair.hidden = true; });
  });

  const liveIntervals = [0, 15, 30];
  const liveStoreKey = "flask_deck_live_" + window.location.pathname;
  let liveIdx = 0;
  let liveTimer = null;
  function applyLiveRefresh(btn, secs, announce) {
    window.clearInterval(liveTimer);
    liveTimer = null;
    const lbl = document.getElementById("dk-live-label");
    if (btn) btn.classList.toggle("dk-live-on", secs > 0);
    if (lbl) lbl.textContent = secs > 0 ? "Live: " + secs + "s" : "Live: Off";
    try {
      if (secs > 0) sessionStorage.setItem(liveStoreKey, String(secs));
      else sessionStorage.removeItem(liveStoreKey);
    } catch (_) {}
    if (secs > 0) {
      liveTimer = window.setInterval(() => window.location.reload(), secs * 1000);
      if (announce) showToast("Auto-refresh every " + secs + "s", "ok");
    }
  }
  function cycleLiveRefresh(btn) {
    liveIdx = (liveIdx + 1) % liveIntervals.length;
    applyLiveRefresh(btn, liveIntervals[liveIdx], true);
  }
  const initLiveBtn = document.querySelector("[data-deck-live-toggle]");
  if (initLiveBtn) {
    let savedSecs = 0;
    try { savedSecs = Number(sessionStorage.getItem(liveStoreKey) || "0"); } catch (_) {}
    const foundIdx = liveIntervals.indexOf(savedSecs);
    if (foundIdx > 0) { liveIdx = foundIdx; applyLiveRefresh(initLiveBtn, savedSecs, false); }
  }

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    if (!t.closest(".dk-popover-wrap")) closePopovers(null);
    if (t.closest("[data-deck-theme-toggle]")) { toggleTheme(); return; }
    if (t.closest("[data-deck-density-toggle]")) { toggleDensity(); return; }
    if (t.closest("[data-deck-rail-toggle]")) { toggleRail(); return; }
    if (t.closest("[data-deck-cmdk-open]")) { openCmdk(); return; }
    if (t.closest("[data-deck-cmdk-close]") || t === cmdkBackdrop) { closeCmdk(); return; }
    if (t.closest("[data-deck-drawer-close]") || t === drawerBackdrop) { closeDrawer(); return; }
    if (t.closest("[data-deck-confirm-close]") || t === confirmBackdrop) { closeConfirm(); return; }
    if (t.closest("[data-deck-keys-open]")) { if (keysBackdrop) keysBackdrop.hidden = false; return; }
    if (t.closest("[data-deck-keys-close]") || t === keysBackdrop) { closeKeys(); return; }
    if (t.closest("[data-deck-notif-open]")) { toggleNotifs(); return; }

    const liveBtn = t.closest("[data-deck-live-toggle]");
    if (liveBtn) { cycleLiveRefresh(liveBtn); return; }

    const copyBtn = t.closest("[data-deck-copy]");
    if (copyBtn) {
      e.preventDefault();
      e.stopPropagation();
      const txt = copyBtn.getAttribute("data-deck-copy") || "";
      if (navigator.clipboard) navigator.clipboard.writeText(txt).then(() => showToast("Copied: " + txt, "ok")).catch(() => {});
      return;
    }

    const drawerBtn = t.closest("[data-deck-drawer-url]");
    if (drawerBtn) { openDrawer(drawerBtn.getAttribute("data-deck-drawer-url"), drawerBtn.getAttribute("data-deck-drawer-title")); return; }

    const toggleEl = t.closest("[data-deck-toggle]");
    if (toggleEl) {
      const target = document.getElementById(toggleEl.getAttribute("data-deck-toggle"));
      if (target) {
        if (target.classList.contains("dk-popover")) closePopovers(target);
        target.hidden = !target.hidden;
      }
      return;
    }

    const tabBtn = t.closest("[data-deck-drawer-tab]");
    if (tabBtn) {
      const tabKey = tabBtn.getAttribute("data-deck-drawer-tab");
      const container = tabBtn.closest("[data-deck-drawer-root]");
      if (container) {
        container.querySelectorAll("[data-deck-drawer-tab]").forEach((b) => b.classList.toggle("is-active", b === tabBtn));
        container.querySelectorAll("[data-deck-drawer-panel]").forEach((p) => { p.hidden = p.getAttribute("data-deck-drawer-panel") !== tabKey; });
      }
      return;
    }

    const confirmFormBtn = t.closest("[data-deck-confirm-form]");
    if (confirmFormBtn) {
      e.preventDefault();
      const form = confirmFormBtn.closest("form");
      if (!form) return;
      const impactUrl = confirmFormBtn.getAttribute("data-impact-url") || "";
      const impactPk = confirmFormBtn.getAttribute("data-impact-pk") || "";
      const rawForce = confirmFormBtn.getAttribute("data-impact-force") || "";
      openConfirm({
        title: confirmFormBtn.getAttribute("data-confirm-title") || "Confirm Action",
        message: confirmFormBtn.getAttribute("data-confirm-msg") || "This action cannot be undone.",
        phrase: confirmFormBtn.getAttribute("data-confirm-phrase") || "",
        demoLocked: confirmFormBtn.getAttribute("data-demo-locked") === "1",
        demoLockMsg: confirmFormBtn.getAttribute("data-demo-lock-msg") || "",
        impactUrl,
        impactBody: impactUrl && impactPk ? { pks: [impactPk], force: rawForce === "1" || rawForce === "true" } : null,
        onConfirm: (txt) => {
          if (txt) {
            let inp = form.querySelector('input[name="confirm_text"]');
            if (!inp) { inp = document.createElement("input"); inp.type = "hidden"; inp.name = "confirm_text"; form.appendChild(inp); }
            inp.value = txt;
          }
          form.submit();
        },
      });
      return;
    }

    const lbBtn = t.closest("[data-deck-lightbox]");
    if (lbBtn) { openLightbox(lbBtn.getAttribute("data-deck-lightbox"), lbBtn.getAttribute("data-lightbox-title")); return; }
    if (t.closest("[data-deck-lightbox-close]") || t === lbBackdrop) { closeLightbox(); return; }

    const fillBtn = t.closest("[data-deck-fill-login]");
    if (fillBtn) {
      const u = document.getElementById("dk-login-user");
      const p = document.getElementById("dk-login-pass");
      if (u) u.value = fillBtn.getAttribute("data-user") || "";
      if (p) p.value = fillBtn.getAttribute("data-pass") || "";
    }
  });

  let pendingG = false;
  let gTimer = null;

  function hasOpenOverlay() {
    return [cmdkBackdrop, drawerBackdrop, confirmBackdrop, keysBackdrop, lbBackdrop].some((el) => el && !el.hidden);
  }
  function isInInput() {
    const active = document.activeElement;
    const tag = (active && active.tagName) || "";
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || Boolean(active && active.isContentEditable);
  }

  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (cmdkBackdrop && !cmdkBackdrop.hidden) closeCmdk(); else openCmdk();
      return;
    }
    if (e.key === "Escape") { closeCmdk(); closeDrawer(); closeConfirm(); closeKeys(); closeLightbox(); closePopovers(null); return; }
    if (isInInput() || e.metaKey || e.ctrlKey || e.altKey || hasOpenOverlay()) return;

    if (pendingG) {
      pendingG = false;
      window.clearTimeout(gTimer);
      const k = e.key.toLowerCase();
      const navLink = Array.from(document.querySelectorAll("[data-go-key]")).find((el) => el.getAttribute("data-go-key") === k);
      if (navLink) { e.preventDefault(); window.location.assign(navLink.getAttribute("href")); }
      return;
    }
    if (e.key === "g") { pendingG = true; gTimer = window.setTimeout(() => { pendingG = false; }, 700); return; }
    if (e.key === "?") { e.preventDefault(); if (keysBackdrop) keysBackdrop.hidden = !keysBackdrop.hidden; return; }
    if (e.key === "t") { e.preventDefault(); toggleTheme(); return; }
    if (e.key === "/") { const s = document.getElementById("dk-table-search"); if (s) { e.preventDefault(); s.focus(); } return; }
    if (e.key === "n") { const nb = document.getElementById("dk-new-record-btn"); if (nb) { e.preventDefault(); window.location.assign(nb.getAttribute("href")); } }
  });

  window.__deck = {
    metaVal,
    CSRF,
    showToast,
    openConfirm,
    closeConfirm,
    openDrawer,
    closeDrawer,
    openLightbox,
    renderSafeMarkdown,
    hasOpenOverlay,
    isInInput,
  };
})();
