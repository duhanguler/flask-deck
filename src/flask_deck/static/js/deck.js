/* Flask-Deck v0.2 — Zero-Dependency, Strict-CSP Client Runtime */
(function () {
  "use strict";

  const root = document.documentElement;
  const metaVal = (n) => { const m = document.querySelector('meta[name="' + n + '"]'); return m ? m.content : ""; };
  const CSRF = metaVal("deck-csrf");
  const SEARCH_URL = metaVal("deck-search-url");
  const NOTIF_URL = metaVal("deck-notif-url");

  /* ---------- Toast Manager (XSS-safe DOM creation) ---------- */
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

  /* ---------- Theme, Density & Rail Toggles ---------- */
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

  /* ---------- Left Rail Model Filter ---------- */
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

  /* ---------- Slide-Over Drawer, Popovers & Keys Modal ---------- */
  const drawerBackdrop = document.getElementById("dk-drawer-backdrop");
  const drawerTitle = document.getElementById("dk-drawer-title");
  const drawerBody = document.getElementById("dk-drawer-body");
  const keysBackdrop = document.getElementById("dk-keys-backdrop");
  let drawerAbort = null;

  function closePopovers(exceptEl) {
    document.querySelectorAll(".dk-popover").forEach((p) => {
      if (p !== exceptEl) p.hidden = true;
    });
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

  /* ---------- Lazy Topbar Notifications Popover ---------- */
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

  /* ---------- Bulk Selection Dock, Parameterized Action & Confirm Modal ---------- */
  const bulkDock = document.getElementById("dk-bulk-dock");
  const bulkCountEl = document.getElementById("dk-bulk-count");
  const confirmBackdrop = document.getElementById("dk-confirm-backdrop");
  const confirmTitle = document.getElementById("dk-confirm-title");
  const confirmMsg = document.getElementById("dk-confirm-msg");
  const confirmFieldsHost = document.getElementById("dk-confirm-fields");
  const confirmPhraseWrap = document.getElementById("dk-confirm-phrase-wrap");
  const confirmPhraseLabel = document.getElementById("dk-confirm-phrase-label");
  const confirmInput = document.getElementById("dk-confirm-input");
  const confirmGo = document.getElementById("dk-confirm-go");
  let pendingConfirmFn = null;

  function selectedPks() {
    return Array.from(document.querySelectorAll("[data-deck-row-check]:checked")).map((cb) => cb.value);
  }
  function syncBulkDock() {
    if (!bulkDock) return;
    const pks = selectedPks();
    bulkDock.hidden = pks.length === 0;
    if (bulkCountEl) bulkCountEl.textContent = pks.length + " selected";
    document.querySelectorAll("[data-deck-row-check]").forEach((cb) => {
      const tr = cb.closest("tr");
      if (tr) tr.classList.toggle("is-selected", cb.checked);
    });
    document.querySelectorAll("[data-deck-export-selected]").forEach((a) => {
      const base = a.getAttribute("data-base-href") || "";
      a.setAttribute("href", base + (base.includes("?") ? "&" : "?") + "ids=" + encodeURIComponent(pks.join(",")));
    });
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
            o.value = val;
            o.textContent = txt;
            if (f.default === val) o.selected = true;
            inp.appendChild(o);
          });
        } else if (f.type === "textarea") {
          inp = document.createElement("textarea");
          inp.className = "dk-textarea";
          inp.value = f.default || "";
          inp.placeholder = f.placeholder || "";
        } else if (f.type === "boolean") {
          inp = document.createElement("input");
          inp.type = "checkbox";
          inp.checked = f.default === true || f.default === "true" || f.default === "1";
        } else {
          inp = document.createElement("input");
          inp.type = f.type === "number" ? "number" : "text";
          inp.className = "dk-input";
          inp.value = f.default || "";
          inp.placeholder = f.placeholder || "";
        }
        fieldInputs[f.name] = { el: inp, spec: f };
        wrap.appendChild(inp);
        confirmFieldsHost.appendChild(wrap);
      });
    }
    const phrase = opts.phrase || "";
    if (confirmPhraseWrap && confirmInput && confirmPhraseLabel) {
      confirmPhraseWrap.hidden = !phrase;
      confirmInput.value = "";
      confirmPhraseLabel.textContent = phrase ? "Type " + phrase + " to confirm:" : "";
      if (confirmGo) confirmGo.disabled = Boolean(phrase);
      confirmInput.oninput = () => { if (confirmGo) confirmGo.disabled = confirmInput.value.trim() !== phrase; };
    }
    pendingConfirmFn = () => {
      const extras = {};
      for (const [k, { el, spec }] of Object.entries(fieldInputs)) {
        if (spec.type === "boolean") {
          extras[k] = el.checked ? "true" : "false";
          continue;
        }
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
  function closeConfirm() { if (confirmBackdrop) confirmBackdrop.hidden = true; pendingConfirmFn = null; }
  if (confirmGo) confirmGo.addEventListener("click", () => { if (typeof pendingConfirmFn === "function") pendingConfirmFn(); });

  function submitBulkAction(actionUrl, confirmText, extraFields) {
    const form = document.getElementById("dk-bulk-form");
    if (!form) return;
    form.action = actionUrl;
    form.querySelectorAll('input:not([name="_csrf_token"])').forEach((n) => n.remove());
    selectedPks().forEach((pk) => {
      const h = document.createElement("input");
      h.type = "hidden";
      h.name = "selected_pks";
      h.value = pk;
      form.appendChild(h);
    });
    if (confirmText) {
      const c = document.createElement("input");
      c.type = "hidden";
      c.name = "confirm_text";
      c.value = confirmText;
      form.appendChild(c);
    }
    Object.entries(extraFields || {}).forEach(([k, v]) => {
      const inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = k;
      inp.value = String(v);
      form.appendChild(inp);
    });
    form.submit();
  }

  /* ---------- Inline Quick-Edit & Kanban Drag-and-Drop ---------- */
  function sendQuickEdit(url, field, value, onSuccess, onError) {
    fetch(url, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-Deck-CSRFToken": CSRF, Accept: "application/json" },
      body: JSON.stringify({ field, value }),
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        if (!ok) {
          showToast(data.error || "Update failed", "danger");
          if (onError) onError();
          return;
        }
        showToast("Updated " + field + " → " + value, "ok");
        if (onSuccess) onSuccess(data);
      })
      .catch(() => { showToast("Network error", "danger"); if (onError) onError(); });
  }

  const kanbanBoard = document.querySelector("[data-deck-kanban]");
  if (kanbanBoard) {
    let draggedCard = null;
    const fieldName = kanbanBoard.getAttribute("data-field") || "status";
    const syncCounts = () => {
      kanbanBoard.querySelectorAll("[data-kanban-col]").forEach((col) => {
        const cnt = col.querySelectorAll("[data-kanban-card]").length;
        const badge = col.querySelector("[data-kanban-count]");
        if (badge) badge.textContent = String(cnt);
        const empty = col.querySelector(".dk-kanban-empty");
        if (empty) empty.hidden = cnt > 0;
      });
    };
    const closestEl = (target, sel) => {
      const el = target instanceof Element ? target : target && target.parentElement;
      return el ? el.closest(sel) : null;
    };
    kanbanBoard.addEventListener("dragstart", (e) => {
      const card = closestEl(e.target, "[data-kanban-card]");
      if (!card || card.getAttribute("draggable") !== "true") return;
      draggedCard = card;
      card.classList.add("is-dragging");
      if (e.dataTransfer) { e.dataTransfer.effectAllowed = "move"; e.dataTransfer.setData("text/plain", card.getAttribute("data-pk") || ""); }
    });
    kanbanBoard.addEventListener("dragend", () => {
      if (draggedCard) draggedCard.classList.remove("is-dragging");
      kanbanBoard.querySelectorAll(".is-drag-over").forEach((z) => z.classList.remove("is-drag-over"));
      draggedCard = null;
    });
    kanbanBoard.addEventListener("dragover", (e) => {
      const dz = closestEl(e.target, "[data-kanban-dropzone]");
      if (!dz || !draggedCard) return;
      e.preventDefault();
      dz.classList.add("is-drag-over");
    });
    kanbanBoard.addEventListener("dragleave", (e) => {
      const dz = closestEl(e.target, "[data-kanban-dropzone]");
      if (dz && (!e.relatedTarget || !dz.contains(e.relatedTarget))) dz.classList.remove("is-drag-over");
    });
    kanbanBoard.addEventListener("drop", (e) => {
      const dz = closestEl(e.target, "[data-kanban-dropzone]");
      if (!dz || !draggedCard) return;
      e.preventDefault();
      dz.classList.remove("is-drag-over");
      const targetVal = dz.getAttribute("data-kanban-dropzone") || "";
      const prevParent = draggedCard.parentElement;
      const card = draggedCard;
      if (prevParent === dz) return;
      dz.prepend(card);
      syncCounts();
      sendQuickEdit(
        card.getAttribute("data-quick-url"),
        fieldName,
        targetVal,
        null,
        () => { if (prevParent) { prevParent.prepend(card); syncCounts(); } }
      );
    });
  }

  /* ---------- Saved Filter Views (localStorage) ---------- */
  const savedBar = document.querySelector("[data-deck-saved-views]");
  const savedHost = document.getElementById("dk-saved-custom-host");
  function renderSavedViews() {
    if (!savedBar || !savedHost) return;
    const slug = savedBar.getAttribute("data-model-slug") || "default";
    const baseUrl = savedBar.getAttribute("data-base-url") || "";
    let list = [];
    try { list = JSON.parse(localStorage.getItem("flask_deck_views_" + slug) || "[]"); } catch (_) {}
    if (!Array.isArray(list)) list = [];
    savedHost.replaceChildren();
    list.forEach((v, idx) => {
      const wrap = document.createElement("span");
      wrap.className = "dk-filter-chip";
      const a = document.createElement("a");
      a.href = baseUrl + (v.qs || "");
      a.textContent = v.name;
      const del = document.createElement("button");
      del.type = "button";
      del.className = "dk-subtle";
      del.textContent = "×";
      del.setAttribute("aria-label", "Remove saved view");
      del.addEventListener("click", () => {
        list.splice(idx, 1);
        try { localStorage.setItem("flask_deck_views_" + slug, JSON.stringify(list)); } catch (_) {}
        renderSavedViews();
      });
      wrap.appendChild(a);
      wrap.appendChild(del);
      savedHost.appendChild(wrap);
    });
    if (list.length > 0) savedBar.hidden = false;
  }
  renderSavedViews();

  /* ---------- Rich Form Widgets (Slider, JSON KV, XSS-Safe Markdown, M2M Filter) ---------- */
  document.querySelectorAll("[data-deck-slider]").forEach((wrap) => {
    const inp = wrap.querySelector("[data-slider-input]");
    const out = wrap.querySelector("[data-slider-val]");
    if (inp && out) inp.addEventListener("input", () => { out.textContent = inp.value + "%"; });
  });

  document.querySelectorAll("[data-deck-m2m]").forEach((wrap) => {
    const flt = wrap.querySelector("[data-m2m-filter]");
    const cnt = wrap.querySelector("[data-m2m-count]");
    if (flt) {
      flt.addEventListener("input", () => {
        const q = flt.value.trim().toLowerCase();
        wrap.querySelectorAll("[data-m2m-item]").forEach((pill) => {
          pill.hidden = Boolean(q) && !(pill.getAttribute("data-m2m-item") || "").includes(q);
        });
      });
    }
    wrap.addEventListener("change", () => {
      if (cnt) cnt.textContent = wrap.querySelectorAll("[data-m2m-check]:checked").length + " selected";
    });
  });

  document.querySelectorAll("[data-deck-json-kv]").forEach((ed) => {
    const rowsHost = ed.querySelector("[data-kv-rows]");
    const rawTa = ed.querySelector("[data-kv-raw]");
    const addBtn = ed.querySelector("[data-kv-add]");
    if (!rowsHost || !rawTa) return;
    const isRo = rawTa.readOnly || rawTa.disabled;
    if (isRo && addBtn) addBtn.hidden = true;
    let kvDirty = false;
    let kvSupported = true;

    function syncToRaw() {
      if (isRo || (!kvSupported && !kvDirty)) return;
      const obj = {};
      rowsHost.querySelectorAll(".dk-kv-row-ed").forEach((r) => {
        const k = r.querySelector("[data-kv-k]").value.trim();
        const vStr = r.querySelector("[data-kv-v]").value;
        if (!k) return;
        const vt = vStr.trim();
        let parsed = vStr;
        if (vt === "true") parsed = true;
        else if (vt === "false") parsed = false;
        else if (vt === "null") parsed = null;
        else if (vt !== "" && !Number.isNaN(Number(vt))) parsed = Number(vt);
        else if ((vt.startsWith("{") && vt.endsWith("}")) || (vt.startsWith("[") && vt.endsWith("]"))) {
          try { parsed = JSON.parse(vt); } catch (_) {}
        }
        obj[k] = parsed;
      });
      rawTa.value = JSON.stringify(obj, null, 2);
    }

    function addRow(k, v) {
      const r = document.createElement("div");
      r.className = "dk-kv-row-ed";
      const ki = document.createElement("input");
      ki.type = "text"; ki.className = "dk-input dk-mono"; ki.placeholder = "key"; ki.value = k || ""; ki.readOnly = isRo; ki.setAttribute("data-kv-k", "");
      const vi = document.createElement("input");
      vi.type = "text"; vi.className = "dk-input dk-mono"; vi.placeholder = "value"; vi.value = v !== undefined ? String(v) : ""; vi.readOnly = isRo; vi.setAttribute("data-kv-v", "");
      r.appendChild(ki); r.appendChild(vi);
      if (!isRo) {
        const rm = document.createElement("button");
        rm.type = "button"; rm.className = "dk-btn dk-btn-ghost dk-btn-icon"; rm.textContent = "×";
        ki.addEventListener("input", () => { kvDirty = true; syncToRaw(); });
        vi.addEventListener("input", () => { kvDirty = true; syncToRaw(); });
        rm.addEventListener("click", () => { kvDirty = true; r.remove(); syncToRaw(); });
        r.appendChild(rm);
      }
      rowsHost.appendChild(r);
    }

    function loadFromRaw() {
      rowsHost.replaceChildren();
      kvDirty = false;
      try {
        const data = JSON.parse(rawTa.value || "{}");
        if (data && typeof data === "object" && !Array.isArray(data)) {
          kvSupported = true;
          const entries = Object.entries(data);
          if (!entries.length && !isRo) addRow("", "");
          else entries.forEach(([k, v]) => addRow(k, v === null ? "null" : (typeof v === "object" ? JSON.stringify(v) : v)));
          return;
        }
      } catch (_) {}
      kvSupported = false;
      addRow("", "");
    }
    loadFromRaw();

    if (addBtn && !isRo) addBtn.addEventListener("click", () => { kvDirty = true; addRow("", ""); });
    ed.querySelectorAll("[data-kv-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mode = btn.getAttribute("data-kv-mode");
        ed.querySelectorAll("[data-kv-mode]").forEach((b) => b.classList.toggle("is-active", b === btn));
        if (mode === "raw") { if (kvDirty) syncToRaw(); rowsHost.hidden = true; rawTa.hidden = false; }
        else { loadFromRaw(); rowsHost.hidden = false; rawTa.hidden = true; }
      });
    });
  });

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

  document.querySelectorAll("[data-deck-md]").forEach((wrap) => {
    const ta = wrap.querySelector("[data-md-input]");
    const prev = wrap.querySelector("[data-md-preview]");
    if (!ta || !prev) return;
    wrap.querySelectorAll("[data-md-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mode = btn.getAttribute("data-md-mode");
        wrap.querySelectorAll("[data-md-mode]").forEach((b) => b.classList.toggle("is-active", b === btn));
        if (mode === "preview") { renderSafeMarkdown(ta.value, prev); ta.hidden = true; prev.hidden = false; }
        else { ta.hidden = false; prev.hidden = true; }
      });
    });
  });

  /* ---------- Column Visibility, FK Combobox & SVG Tooltips ---------- */
  const colMenu = document.querySelector("[data-deck-cols-menu]");
  if (colMenu) {
    const storageKey = "flask_deck_cols_" + (colMenu.getAttribute("data-model-slug") || "default");
    const applyHidden = (hiddenSet) => {
      document.querySelectorAll("[data-col]").forEach((el) => el.classList.toggle("dk-col-hidden", hiddenSet.has(el.getAttribute("data-col"))));
    };
    let saved = new Set();
    try { const raw = JSON.parse(localStorage.getItem(storageKey) || "[]"); if (Array.isArray(raw)) saved = new Set(raw); } catch (_) {}
    colMenu.querySelectorAll("[data-col-toggle]").forEach((cb) => {
      const col = cb.getAttribute("data-col-toggle");
      cb.checked = !saved.has(col);
      cb.addEventListener("change", () => {
        if (cb.checked) saved.delete(col); else saved.add(col);
        try { localStorage.setItem(storageKey, JSON.stringify(Array.from(saved))); } catch (_) {}
        applyHidden(saved);
      });
    });
    if (saved.size) applyHidden(saved);
  }

  document.querySelectorAll("[data-deck-fk]").forEach((wrap) => {
    const searchInput = wrap.querySelector("[data-fk-search]");
    const hiddenInput = wrap.querySelector("[data-fk-value]");
    const dropdown = wrap.querySelector("[data-fk-dropdown]");
    const apiUrl = wrap.getAttribute("data-fk-url") || "";
    let depSpec = null;
    try { const rawDep = wrap.getAttribute("data-dependent"); if (rawDep) depSpec = JSON.parse(rawDep); } catch (_) {}
    if (!searchInput || !hiddenInput || !dropdown) return;
    let fkAbort = null;
    const ownerForm = wrap.closest("form") || document;
    const initialOpts = Array.from(dropdown.querySelectorAll(".dk-fk-opt")).map((el) => ({
      id: el.getAttribute("data-id") || "",
      label: el.getAttribute("data-label") || "",
    }));
    function readParentVal(name) {
      const r = ownerForm.querySelector('input[type="radio"][name="' + name + '"]:checked');
      if (r) return r.value;
      const el = ownerForm.querySelector('[name="' + name + '"]');
      if (!el || el.type === "radio") return "";
      return el.type === "checkbox" ? (el.checked ? "true" : "false") : el.value;
    }
    function renderOpts(items) {
      dropdown.replaceChildren();
      if (!items.length) { const e = document.createElement("div"); e.className = "dk-fk-opt dk-muted"; e.textContent = "No matches"; dropdown.appendChild(e); return; }
      items.forEach((it) => {
        const row = document.createElement("div");
        row.className = "dk-fk-opt";
        const lbl = document.createElement("span"); lbl.textContent = it.label;
        const idEl = document.createElement("span"); idEl.className = "dk-mono dk-subtle"; idEl.textContent = "#" + it.id;
        row.appendChild(lbl); row.appendChild(idEl);
        row.addEventListener("mousedown", (e) => {
          e.preventDefault();
          hiddenInput.value = it.id;
          searchInput.value = it.label;
          dropdown.hidden = true;
          hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
        });
        dropdown.appendChild(row);
      });
    }
    function fetchRemote(q) {
      if (searchInput.readOnly) return;
      if (!apiUrl) { renderOpts(initialOpts.filter((o) => o.label.toLowerCase().includes(q.toLowerCase()))); dropdown.hidden = false; return; }
      let url = apiUrl + (apiUrl.includes("?") ? "&" : "?") + "q=" + encodeURIComponent(q);
      if (depSpec && depSpec.parent && depSpec.filter_col) {
        const pVal = readParentVal(depSpec.parent);
        if (pVal) url += "&dep_col=" + encodeURIComponent(depSpec.filter_col) + "&dep_val=" + encodeURIComponent(pVal);
      }
      if (fkAbort) fkAbort.abort();
      fkAbort = new AbortController();
      fetch(url, { headers: { Accept: "application/json" }, signal: fkAbort.signal })
        .then((r) => (r.ok ? r.json() : { items: [] }))
        .then((d) => {
          if (document.activeElement !== searchInput) return;
          renderOpts(Array.isArray(d.items) ? d.items : []);
          dropdown.hidden = false;
        })
        .catch(() => {});
    }
    if (depSpec && depSpec.parent) {
      ownerForm.addEventListener("change", (ev) => {
        if (ev.target && ev.target.name === depSpec.parent) {
          hiddenInput.value = "";
          searchInput.value = "";
          hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
        }
      });
    }
    searchInput.addEventListener("focus", () => {
      if (searchInput.readOnly) return;
      if (depSpec && apiUrl) fetchRemote("");
      else { renderOpts(initialOpts); dropdown.hidden = false; }
    });
    searchInput.addEventListener("blur", () => { window.setTimeout(() => { dropdown.hidden = true; }, 140); });
    let fkTimer = null;
    searchInput.addEventListener("input", () => {
      if (searchInput.readOnly) return;
      const q = searchInput.value.trim();
      if (!q && hiddenInput.value) {
        hiddenInput.value = "";
        hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
      }
      window.clearTimeout(fkTimer);
      fkTimer = window.setTimeout(() => fetchRemote(q), 140);
    });
  });

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

  /* ---------- Dashboard Live Auto-Refresh ---------- */
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

  /* ---------- Global Click & Change Delegation ---------- */
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

    const sqlPreset = t.closest("[data-deck-sql-preset]");
    if (sqlPreset) {
      const ed = document.getElementById("dk-sql-editor");
      if (ed) { ed.value = sqlPreset.getAttribute("data-deck-sql-preset") || ""; ed.focus(); }
      return;
    }

    const saveViewBtn = t.closest("[data-deck-save-view]");
    if (saveViewBtn) {
      const slug = saveViewBtn.getAttribute("data-model-slug") || "default";
      const name = window.prompt("Name for this saved view:");
      if (!name || !name.trim()) return;
      let list = [];
      try { list = JSON.parse(localStorage.getItem("flask_deck_views_" + slug) || "[]"); } catch (_) {}
      list.push({ name: name.trim().slice(0, 32), qs: window.location.search || "" });
      try { localStorage.setItem("flask_deck_views_" + slug, JSON.stringify(list.slice(-8))); } catch (_) {}
      renderSavedViews();
      showToast("Saved view '" + name.trim() + "'", "ok");
      return;
    }

    const formTabBtn = t.closest("[data-deck-form-tab]");
    if (formTabBtn) {
      const key = formTabBtn.getAttribute("data-deck-form-tab");
      const rootForm = formTabBtn.closest("[data-deck-form-root]");
      if (rootForm && !rootForm.hasAttribute("data-deck-wizard")) {
        rootForm.querySelectorAll("[data-deck-form-tab]").forEach((b) => b.classList.toggle("is-active", b === formTabBtn));
        rootForm.querySelectorAll("[data-deck-form-panel]").forEach((p) => { p.hidden = p.getAttribute("data-deck-form-panel") !== key; });
      }
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

    const qeBtn = t.closest("[data-deck-quick-edit]");
    if (qeBtn) {
      sendQuickEdit(qeBtn.getAttribute("data-url"), qeBtn.getAttribute("data-field"), qeBtn.getAttribute("data-next") === "true", (data) => {
        qeBtn.setAttribute("data-next", data.value ? "false" : "true");
        const doc = new DOMParser().parseFromString(data.display || "", "text/html");
        qeBtn.replaceChildren(...Array.from(doc.body.childNodes));
      });
      return;
    }

    const bulkBtn = t.closest("[data-deck-bulk-action]");
    if (bulkBtn) {
      const url = bulkBtn.getAttribute("data-url");
      const label = bulkBtn.getAttribute("data-label") || "Execute Action";
      const needConfirm = bulkBtn.getAttribute("data-confirm") === "true";
      const phraseTpl = bulkBtn.getAttribute("data-confirm-phrase") || "";
      const rawFields = bulkBtn.getAttribute("data-action-fields") || "";
      let fields = [];
      if (rawFields) { try { fields = JSON.parse(rawFields); } catch (_) {} }
      const count = selectedPks().length;
      const phrase = phraseTpl ? phraseTpl.replace("{n}", String(count)) : "";
      if (needConfirm || phrase || fields.length) {
        openConfirm({
          title: label,
          message: "Apply '" + label + "' to " + count + " selected record(s)?",
          phrase,
          fields,
          onConfirm: (txt, extras) => submitBulkAction(url, txt, extras),
        });
      } else {
        submitBulkAction(url, "", {});
      }
      return;
    }

    const confirmFormBtn = t.closest("[data-deck-confirm-form]");
    if (confirmFormBtn) {
      e.preventDefault();
      const form = confirmFormBtn.closest("form");
      if (!form) return;
      openConfirm({
        title: confirmFormBtn.getAttribute("data-confirm-title") || "Confirm Action",
        message: confirmFormBtn.getAttribute("data-confirm-msg") || "This action cannot be undone.",
        phrase: confirmFormBtn.getAttribute("data-confirm-phrase") || "",
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

    const addInlineBtn = t.closest("[data-deck-add-inline]");
    if (addInlineBtn) {
      const slug = addInlineBtn.getAttribute("data-deck-add-inline");
      const tpl = document.querySelector('template[data-inline-template="' + slug + '"]');
      const tbody = document.querySelector('tbody[data-inline-body="' + slug + '"]');
      if (tpl && tbody) {
        const nextIdx = Number(tbody.getAttribute("data-next-index") || "0");
        tbody.setAttribute("data-next-index", String(nextIdx + 1));
        const frag = tpl.content.cloneNode(true);
        frag.querySelectorAll("[name]").forEach((el) => el.setAttribute("name", el.getAttribute("name").replace("__INDEX__", String(nextIdx))));
        tbody.appendChild(frag);
      }
      return;
    }

    const delInlineBtn = t.closest("[data-deck-del-inline]");
    if (delInlineBtn) {
      const tr = delInlineBtn.closest("tr");
      if (!tr) return;
      const delInput = tr.querySelector("[data-inline-del-flag]");
      if (delInput) {
        const isMarked = delInput.value === "1";
        delInput.value = isMarked ? "0" : "1";
        tr.classList.toggle("dk-inline-deleted", !isMarked);
      } else tr.remove();
      return;
    }

    const prettyBtn = t.closest("[data-deck-pretty-json]");
    if (prettyBtn) {
      const ta = document.getElementById(prettyBtn.getAttribute("data-deck-pretty-json"));
      if (ta) { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); showToast("Formatted JSON", "ok"); } catch (_) { showToast("Invalid JSON syntax", "danger"); } }
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

  /* ---------- v0.3.0: Lightbox, Dropzone, ARRAY Tags, show_when, Wizard, Rule Builder & SSE Jobs ---------- */
  const lbBackdrop = document.getElementById("dk-lightbox-backdrop");
  const lbImg = document.getElementById("dk-lightbox-img");
  const lbTitle = document.getElementById("dk-lightbox-title");
  const lbDl = document.getElementById("dk-lightbox-dl");
  let lbPrevFocus = null;
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

  document.querySelectorAll("[data-deck-dropzone]").forEach((dz) => {
    const inp = dz.querySelector("[data-dz-input]");
    const nameEl = dz.querySelector("[data-dz-name]");
    const prevImg = dz.querySelector("[data-dz-preview]");
    const clearCb = dz.querySelector('input[type="checkbox"][name^="_clear_"]');
    if (!inp) return;
    const origName = nameEl ? nameEl.textContent : "";
    function clearPreview() {
      if (prevImg) { prevImg.hidden = true; prevImg.removeAttribute("src"); }
    }
    function handleFile(file) {
      if (!file) return;
      if (clearCb) clearCb.checked = false;
      if (nameEl) nameEl.textContent = file.name + " (" + Math.max(1, Math.round(file.size / 1024)) + " KB)";
      if (prevImg && file.type && file.type.startsWith("image/") && file.type !== "image/svg+xml") {
        const reader = new FileReader();
        reader.onload = () => { prevImg.src = String(reader.result || ""); prevImg.hidden = false; };
        reader.readAsDataURL(file);
      } else {
        clearPreview();
      }
    }
    if (clearCb) {
      clearCb.addEventListener("change", () => {
        if (clearCb.checked) { inp.value = ""; clearPreview(); if (nameEl) nameEl.textContent = origName; }
      });
    }
    inp.addEventListener("change", () => { if (inp.files && inp.files[0]) handleFile(inp.files[0]); else clearPreview(); });
    dz.addEventListener("dragover", (e) => { if (inp.disabled) return; e.preventDefault(); dz.classList.add("is-dragover"); });
    dz.addEventListener("dragleave", (e) => { if (!e.relatedTarget || !dz.contains(e.relatedTarget)) dz.classList.remove("is-dragover"); });
    dz.addEventListener("drop", (e) => {
      e.preventDefault();
      dz.classList.remove("is-dragover");
      if (inp.disabled || !e.dataTransfer || !e.dataTransfer.files || !e.dataTransfer.files[0]) return;
      const file = e.dataTransfer.files[0];
      try {
        if (typeof DataTransfer !== "undefined") {
          const dt = new DataTransfer();
          dt.items.add(file);
          inp.files = dt.files;
        } else {
          inp.files = e.dataTransfer.files;
        }
      } catch (_) {
        showToast("Browser blocked drag-and-drop; use Choose File instead.", "warn");
        return;
      }
      handleFile(file);
    });
  });

  document.querySelectorAll("[data-deck-tags]").forEach((wrap) => {
    const hid = wrap.querySelector("[data-tags-hidden]");
    const host = wrap.querySelector("[data-tags-chips]");
    const inp = wrap.querySelector("[data-tags-input]");
    if (!hid || !host || !inp) return;
    const isRo = inp.readOnly || inp.disabled;
    let items = [];
    try { const p = JSON.parse(hid.value || "[]"); if (Array.isArray(p)) items = p.map(String); } catch (_) {}
    function sync() {
      hid.value = JSON.stringify(items);
      host.replaceChildren();
      items.forEach((val, idx) => {
        const pill = document.createElement("span");
        pill.className = "dk-filter-chip dk-mono";
        const sp = document.createElement("span"); sp.textContent = val;
        pill.appendChild(sp);
        if (!isRo) {
          const rm = document.createElement("button"); rm.type = "button"; rm.className = "dk-subtle"; rm.textContent = "×";
          rm.setAttribute("aria-label", "Remove tag");
          rm.addEventListener("click", () => { items.splice(idx, 1); sync(); });
          pill.appendChild(rm);
        }
        host.appendChild(pill);
      });
    }
    function commitInput() {
      if (isRo || !inp.value.trim()) return;
      let changed = false;
      inp.value.split(",").forEach((part) => {
        const v = part.trim();
        if (v && !items.includes(v)) { items.push(v); changed = true; }
      });
      inp.value = "";
      if (changed) sync();
    }
    if (!isRo) {
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === ",") { e.preventDefault(); commitInput(); }
        else if (e.key === "Backspace" && !inp.value && items.length) { items.pop(); sync(); }
      });
      inp.addEventListener("blur", commitInput);
      const pf = wrap.closest("form");
      if (pf) pf.addEventListener("submit", commitInput);
    }
    sync();
  });

  const formRoot = document.querySelector("[data-deck-form-root]");
  if (formRoot) {
    function getFieldVal(name) {
      const radio = formRoot.querySelector('input[type="radio"][name="' + name + '"]:checked');
      if (radio) return radio.value;
      const el = formRoot.querySelector('[name="' + name + '"]');
      if (!el || el.type === "radio") return "";
      if (el.type === "checkbox") return el.checked;
      return el.value;
    }
    function evalShowWhen() {
      formRoot.querySelectorAll("[data-show-when]").forEach((fld) => {
        let rule = null;
        try { rule = JSON.parse(fld.getAttribute("data-show-when") || "null"); } catch (_) {}
        if (!rule || !rule.field) return;
        const cur = getFieldVal(rule.field);
        let ok = true;
        if (rule.op === "eq") ok = String(cur) === String(rule.value);
        else if (rule.op === "neq") ok = String(cur) !== String(rule.value);
        else if (rule.op === "in" && Array.isArray(rule.value)) ok = rule.value.map(String).includes(String(cur));
        else if (rule.op === "truthy") ok = Boolean(cur);
        else if (rule.op === "falsy") ok = !cur;
        fld.hidden = !ok;
        fld.querySelectorAll("input, select, textarea").forEach((ctrl) => {
          if (ctrl.required && !ctrl.hasAttribute("data-deck-was-required")) {
            ctrl.setAttribute("data-deck-was-required", "1");
          }
          if (ctrl.getAttribute("data-deck-was-required") === "1") {
            ctrl.required = ok;
          }
        });
      });
    }
    formRoot.addEventListener("change", evalShowWhen);
    formRoot.addEventListener("input", evalShowWhen);
    evalShowWhen();

    const panels = Array.from(formRoot.querySelectorAll("[data-deck-form-panel]"));
    const tabBtns = Array.from(formRoot.querySelectorAll("[data-deck-form-tab]"));
    const isWizard = formRoot.hasAttribute("data-deck-wizard");
    let showPanelAt = null;

    if (isWizard && panels.length) {
      const steps = Array.from(formRoot.querySelectorAll("[data-wiz-idx]"));
      const prevBtn = formRoot.querySelector("[data-wiz-prev]");
      const nextBtn = formRoot.querySelector("[data-wiz-next]");
      const subBtn = formRoot.querySelector("[data-wiz-submit]");
      let curStep = 0;
      const errPanelIdx = panels.findIndex((p) => p.querySelector(".dk-field-err"));
      if (errPanelIdx > 0) curStep = errPanelIdx;
      function validateStep(idx) {
        const controls = Array.from(panels[idx].querySelectorAll("input, select, textarea"));
        for (const c of controls) {
          if (!c.disabled && !c.closest("[hidden]") && typeof c.checkValidity === "function" && !c.checkValidity()) {
            c.reportValidity();
            return false;
          }
        }
        return true;
      }
      function showStep(idx) {
        curStep = Math.max(0, Math.min(panels.length - 1, idx));
        steps.forEach((b, i) => b.classList.toggle("is-active", i === curStep));
        panels.forEach((p, i) => { p.hidden = i !== curStep; });
        if (prevBtn) prevBtn.hidden = curStep === 0;
        if (nextBtn) nextBtn.hidden = curStep >= panels.length - 1;
        if (subBtn) subBtn.hidden = curStep < panels.length - 1;
      }
      showPanelAt = showStep;
      steps.forEach((b, i) => b.addEventListener("click", () => { if (i <= curStep || validateStep(curStep)) showStep(i); }));
      if (prevBtn) prevBtn.addEventListener("click", () => showStep(curStep - 1));
      if (nextBtn) nextBtn.addEventListener("click", () => { if (validateStep(curStep)) showStep(curStep + 1); });
      formRoot.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && curStep < panels.length - 1 && e.target && e.target.tagName === "INPUT" && !e.target.hasAttribute("data-tags-input")) {
          e.preventDefault();
          if (validateStep(curStep)) showStep(curStep + 1);
        }
      });
      showStep(curStep);
    } else if (panels.length && tabBtns.length) {
      showPanelAt = (idx) => {
        const key = panels[idx]?.getAttribute("data-deck-form-panel");
        tabBtns.forEach((b) => b.classList.toggle("is-active", b.getAttribute("data-deck-form-tab") === key));
        panels.forEach((p, i) => { p.hidden = i !== idx; });
      };
      const errPanelIdx = panels.findIndex((p) => p.querySelector(".dk-field-err"));
      if (errPanelIdx > 0) showPanelAt(errPanelIdx);
    }

    if (showPanelAt) {
      formRoot.addEventListener("invalid", (e) => {
        const p = e.target && e.target.closest ? e.target.closest("[data-deck-form-panel]") : null;
        if (p && p.hidden) {
          const idx = panels.indexOf(p);
          if (idx >= 0) { showPanelAt(idx); window.setTimeout(() => { try { e.target.focus(); } catch (_) {} }, 0); }
        }
      }, true);
    }
  }

  document.querySelectorAll("[data-deck-rule-builder]").forEach((rb) => {
    const fSel = rb.querySelector("[data-rule-field]");
    const oSel = rb.querySelector("[data-rule-op]");
    const vInp = rb.querySelector("[data-rule-val]");
    const addBtn = rb.querySelector("[data-rule-add]");
    const hidHost = rb.querySelector("[data-rule-hidden]");
    if (!fSel || !oSel || !vInp || !addBtn || !hidHost) return;
    const syncOpUi = () => {
      const isNullOp = oSel.value === "__null";
      vInp.placeholder = isNullOp ? "true / false (default true)" : "Value";
    };
    oSel.addEventListener("change", syncOpUi);
    syncOpUi();
    addBtn.addEventListener("click", () => {
      const f = fSel.value;
      const op = oSel.value;
      let val = vInp.value.trim();
      if (op === "__null" && !val) val = "true";
      if (!f || !val) { showToast("Choose a field and value", "warn"); return; }
      const inp = document.createElement("input");
      inp.type = "hidden";
      inp.name = "f_" + f + op;
      inp.value = val;
      inp.setAttribute("data-rule-staged", "1");
      hidHost.appendChild(inp);
      const chip = document.createElement("span");
      chip.className = "dk-filter-chip dk-mono";
      const sp = document.createElement("span");
      sp.textContent = f + (op || "=") + " " + val;
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "dk-subtle";
      rm.textContent = "×";
      rm.setAttribute("aria-label", "Remove condition");
      rm.addEventListener("click", () => { inp.remove(); chip.remove(); });
      chip.appendChild(sp);
      chip.appendChild(rm);
      hidHost.appendChild(chip);
      vInp.value = "";
    });
    const filterForm = rb.closest("form");
    if (filterForm) {
      filterForm.addEventListener("submit", () => {
        const stagedNames = new Set(
          Array.from(hidHost.querySelectorAll('input[data-rule-staged="1"]')).map((el) => el.name)
        );
        filterForm.querySelectorAll('input[name^="f_"], select[name^="f_"]').forEach((ctrl) => {
          if (ctrl.hasAttribute("data-rule-staged")) return;
          if (!String(ctrl.value || "").trim() && stagedNames.has(ctrl.name)) ctrl.disabled = true;
        });
      });
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
      const es = new EventSource(streamUrl);
      activeStreams.push(es);
      es.onmessage = (ev) => {
        let data = null;
        try { data = JSON.parse(ev.data); } catch (_) { return; }
        applyJob(data);
        if (done) es.close();
      };
      es.onerror = () => {
        es.close();
        if (!done) startPoll();
      };
    } else {
      startPoll();
    }
  });
  window.addEventListener("pagehide", () => {
    activeStreams.forEach((es) => { try { es.close(); } catch (_) {} });
    activePollers.forEach((tid) => window.clearInterval(tid));
  });

  document.querySelectorAll("[data-deck-quick-select]").forEach((sel) => {
    sel.setAttribute("data-prev-val", sel.value);
    sel.addEventListener("focus", () => sel.setAttribute("data-prev-val", sel.value));
  });

  document.addEventListener("change", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    if (t.matches("[data-deck-select-all]")) { document.querySelectorAll("[data-deck-row-check]").forEach((cb) => { cb.checked = t.checked; }); syncBulkDock(); return; }
    if (t.matches("[data-deck-row-check]")) { syncBulkDock(); return; }
    if (t.matches("[data-deck-quick-select]")) {
      const prev = t.getAttribute("data-prev-val");
      const next = t.value;
      sendQuickEdit(
        t.getAttribute("data-url"),
        t.getAttribute("data-field"),
        next,
        () => { t.setAttribute("data-prev-val", next); },
        () => { if (prev !== null) t.value = prev; }
      );
      return;
    }
    if (t.matches('.dk-switch input[type="checkbox"]')) {
      const row = t.closest(".dk-switch-row");
      const lbl = row && row.querySelector("[data-switch-label]");
      if (lbl) lbl.textContent = t.checked ? "Enabled" : "Disabled";
    }
  });

  /* ---------- Linear-Style Keyboard Navigation (⌘K, /, n, t, ?, j/k/Space/x/e, g+key) ---------- */
  let kbRowIdx = -1;
  let pendingG = false;
  let gTimer = null;

  function hasOpenOverlay() {
    return [cmdkBackdrop, drawerBackdrop, confirmBackdrop, keysBackdrop, lbBackdrop].some((el) => el && !el.hidden);
  }

  document.addEventListener("keydown", (e) => {
    const active = document.activeElement;
    const tag = (active && active.tagName) || "";
    const inInput = tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || Boolean(active && active.isContentEditable);

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (cmdkBackdrop && !cmdkBackdrop.hidden) closeCmdk(); else openCmdk();
      return;
    }
    if (e.key === "Escape") { closeCmdk(); closeDrawer(); closeConfirm(); closeKeys(); closeLightbox(); closePopovers(null); return; }
    if (inInput || e.metaKey || e.ctrlKey || e.altKey || hasOpenOverlay()) return;

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
    if (e.key === "n") { const nb = document.getElementById("dk-new-record-btn"); if (nb) { e.preventDefault(); window.location.assign(nb.getAttribute("href")); } return; }

    const rows = Array.from(document.querySelectorAll("[data-deck-row-nav]"));
    if (!rows.length) return;
    const onInteractive = tag === "BUTTON" || tag === "A" || tag === "SUMMARY";
    if (e.key === "j" || e.key === "k") {
      e.preventDefault();
      kbRowIdx = e.key === "j" ? Math.min(rows.length - 1, kbRowIdx + 1) : Math.max(0, kbRowIdx - 1);
      rows.forEach((r, i) => r.classList.toggle("is-kb-focus", i === kbRowIdx));
      rows[kbRowIdx]?.scrollIntoView({ block: "nearest" });
    } else if (kbRowIdx >= 0 && rows[kbRowIdx]) {
      const row = rows[kbRowIdx];
      if (e.key === " " && !onInteractive) { e.preventDefault(); openDrawer(row.getAttribute("data-drawer-url"), row.getAttribute("data-drawer-title")); }
      else if (e.key === "Enter" && !onInteractive) { e.preventDefault(); window.location.assign(row.getAttribute("data-detail-url")); }
      else if (e.key === "e" && row.getAttribute("data-edit-url")) { e.preventDefault(); window.location.assign(row.getAttribute("data-edit-url")); }
      else if (e.key === "x") {
        e.preventDefault();
        const cb = row.querySelector("[data-deck-row-check]");
        if (cb) { cb.checked = !cb.checked; syncBulkDock(); }
      }
    }
  });
})();
