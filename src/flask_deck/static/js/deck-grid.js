/* Flask-Deck — Data Grid, Kanban, Saved Views, Rule Builder & Bulk Dock */
(function () {
  "use strict";
  const D = window.__deck;
  if (!D) return;

  const bulkDock = document.getElementById("dk-bulk-dock");
  const bulkCountEl = document.getElementById("dk-bulk-count");

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

  function submitBulkAction(actionUrl, confirmText, extraFields) {
    const form = document.getElementById("dk-bulk-form");
    if (!form) return;
    form.action = actionUrl;
    form.querySelectorAll('input:not([name="_csrf_token"])').forEach((n) => n.remove());
    selectedPks().forEach((pk) => {
      const h = document.createElement("input");
      h.type = "hidden"; h.name = "selected_pks"; h.value = pk;
      form.appendChild(h);
    });
    if (confirmText) {
      const c = document.createElement("input");
      c.type = "hidden"; c.name = "confirm_text"; c.value = confirmText;
      form.appendChild(c);
    }
    Object.entries(extraFields || {}).forEach(([k, v]) => {
      const inp = document.createElement("input");
      inp.type = "hidden"; inp.name = k; inp.value = String(v);
      form.appendChild(inp);
    });
    form.submit();
  }

  function sendQuickEdit(url, field, value, onSuccess, onError) {
    fetch(url, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-Deck-CSRFToken": D.CSRF, Accept: "application/json" },
      body: JSON.stringify({ field, value }),
    })
      .then((r) => r.json().then((d) => ({ ok: r.ok, data: d })))
      .then(({ ok, data }) => {
        if (!ok) {
          D.showToast(data.error || "Update failed", "danger");
          if (onError) onError();
          return;
        }
        D.showToast("Updated " + field + " → " + value, "ok");
        if (onSuccess) onSuccess(data);
      })
      .catch(() => { D.showToast("Network error", "danger"); if (onError) onError(); });
  }
  D.sendQuickEdit = sendQuickEdit;

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
      if (!f || !val) { D.showToast("Choose a field and value", "warn"); return; }
      const inp = document.createElement("input");
      inp.type = "hidden"; inp.name = "f_" + f + op; inp.value = val;
      inp.setAttribute("data-rule-staged", "1");
      hidHost.appendChild(inp);
      const chip = document.createElement("span");
      chip.className = "dk-filter-chip dk-mono";
      const sp = document.createElement("span");
      sp.textContent = f + (op || "=") + " " + val;
      const rm = document.createElement("button");
      rm.type = "button"; rm.className = "dk-subtle"; rm.textContent = "×";
      rm.setAttribute("aria-label", "Remove condition");
      rm.addEventListener("click", () => { inp.remove(); chip.remove(); });
      chip.appendChild(sp); chip.appendChild(rm);
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

  document.querySelectorAll("[data-deck-quick-select]").forEach((sel) => {
    sel.setAttribute("data-prev-val", sel.value);
    sel.addEventListener("focus", () => sel.setAttribute("data-prev-val", sel.value));
  });

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

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
      D.showToast("Saved view '" + name.trim() + "'", "ok");
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
        D.openConfirm({
          title: label,
          message: "Apply '" + label + "' to " + count + " selected record(s)?",
          phrase,
          fields,
          onConfirm: (txt, extras) => submitBulkAction(url, txt, extras),
        });
      } else {
        submitBulkAction(url, "", {});
      }
    }
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
    if (t.matches("[data-deck-quick-input]")) {
      const prev = t.getAttribute("data-prev-val") || "";
      const next = t.value;
      if (next === prev) return;
      sendQuickEdit(
        t.getAttribute("data-url"),
        t.getAttribute("data-field"),
        next,
        () => { t.setAttribute("data-prev-val", next); },
        () => { t.value = prev; }
      );
    }
  });

  let kbRowIdx = -1;
  document.addEventListener("keydown", (e) => {
    const ae = document.activeElement;
    if (e.key === "Enter" && ae instanceof Element && ae.matches("[data-deck-quick-input]")) {
      e.preventDefault();
      if (ae instanceof HTMLElement) ae.blur();
      return;
    }
    if (D.isInInput() || e.metaKey || e.ctrlKey || e.altKey || D.hasOpenOverlay()) return;
    const rows = Array.from(document.querySelectorAll("[data-deck-row-nav]"));
    if (!rows.length) return;
    const active = document.activeElement;
    const tag = (active && active.tagName) || "";
    const onInteractive = tag === "BUTTON" || tag === "A" || tag === "SUMMARY";
    if (e.key === "j" || e.key === "k") {
      e.preventDefault();
      kbRowIdx = e.key === "j" ? Math.min(rows.length - 1, kbRowIdx + 1) : Math.max(0, kbRowIdx - 1);
      rows.forEach((r, i) => r.classList.toggle("is-kb-focus", i === kbRowIdx));
      rows[kbRowIdx]?.scrollIntoView({ block: "nearest" });
    } else if (kbRowIdx >= 0 && rows[kbRowIdx]) {
      const row = rows[kbRowIdx];
      if (e.key === " " && !onInteractive) { e.preventDefault(); D.openDrawer(row.getAttribute("data-drawer-url"), row.getAttribute("data-drawer-title")); }
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
