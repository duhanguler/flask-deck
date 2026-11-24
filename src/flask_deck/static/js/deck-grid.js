/* Flask-Deck — Data Grid, Kanban, Saved Views, Rule Builder & Bulk Dock */
(function () {
  "use strict";
  const D = window.__deck;
  if (!D) return;

  const bulkDock = document.getElementById("dk-bulk-dock");
  const bulkCountEl = document.getElementById("dk-bulk-count");
  const selectAcrossBar = document.getElementById("dk-select-across-bar");
  const selectAcrossBtn = document.getElementById("dk-select-across-btn");
  const selectAcrossMsg = document.getElementById("dk-select-across-msg");
  const selectAcrossTotal = selectAcrossBar ? Number(selectAcrossBar.getAttribute("data-total") || "0") : 0;
  const selectAcrossPageCount = selectAcrossBar ? Number(selectAcrossBar.getAttribute("data-page-count") || "0") : 0;
  const selectAcrossToken = selectAcrossBar ? (selectAcrossBar.getAttribute("data-slice-token") || "") : "";
  let selectAcrossActive = false;

  function selectedPks() {
    return Array.from(document.querySelectorAll("[data-deck-row-check]:checked")).map((cb) => cb.value);
  }
  function updateSelectAcrossUI(pks) {
    if (!selectAcrossBar) return;
    const allChecked = selectAcrossPageCount > 0 && pks.length === selectAcrossPageCount && selectAcrossTotal > selectAcrossPageCount;
    if (!allChecked) selectAcrossActive = false;
    selectAcrossBar.hidden = !allChecked;
    if (selectAcrossMsg && selectAcrossBtn) {
      if (selectAcrossActive) {
        selectAcrossMsg.textContent = "All " + selectAcrossTotal.toLocaleString() + " matching records across pages are selected.";
        selectAcrossBtn.textContent = "Clear full selection";
      } else {
        selectAcrossMsg.textContent = "All " + selectAcrossPageCount + " records on this page are selected.";
        selectAcrossBtn.textContent = "Select all " + selectAcrossTotal.toLocaleString() + " matching records";
      }
    }
  }
  function syncBulkDock() {
    if (!bulkDock) return;
    const pks = selectedPks();
    updateSelectAcrossUI(pks);
    bulkDock.hidden = pks.length === 0 && !selectAcrossActive;
    if (bulkCountEl) {
      bulkCountEl.textContent = selectAcrossActive
        ? selectAcrossTotal.toLocaleString() + " matching selected"
        : pks.length + " selected";
    }
    document.querySelectorAll("[data-deck-row-check]").forEach((cb) => {
      const tr = cb.closest("tr");
      if (tr) tr.classList.toggle("is-selected", cb.checked);
    });
    document.querySelectorAll("[data-deck-export-selected]").forEach((a) => {
      if (selectAcrossActive && selectAcrossToken) {
        const filtBase = a.getAttribute("data-base-filtered-href") || a.getAttribute("data-base-href") || "";
        a.setAttribute("href", filtBase + (filtBase.includes("?") ? "&" : "?") + "select_across=1&slice_token=" + encodeURIComponent(selectAcrossToken));
      } else {
        const base = a.getAttribute("data-base-href") || "";
        a.setAttribute("href", base + (base.includes("?") ? "&" : "?") + "ids=" + encodeURIComponent(pks.join(",")));
      }
    });
  }
  if (selectAcrossBtn) {
    selectAcrossBtn.addEventListener("click", () => {
      selectAcrossActive = !selectAcrossActive;
      syncBulkDock();
    });
  }

  function submitBulkAction(actionUrl, confirmText, extraFields) {
    const form = document.getElementById("dk-bulk-form");
    if (!form) return;
    form.action = actionUrl;
    form.querySelectorAll('input:not([name="_csrf_token"])').forEach((n) => n.remove());
    const retQs = form.getAttribute("data-return-qs") || "";
    if (retQs) {
      const r = document.createElement("input");
      r.type = "hidden"; r.name = "_return_qs"; r.value = retQs;
      form.appendChild(r);
    }
    if (selectAcrossActive && selectAcrossToken) {
      const sa = document.createElement("input");
      sa.type = "hidden"; sa.name = "select_across"; sa.value = "1";
      const tk = document.createElement("input");
      tk.type = "hidden"; tk.name = "slice_token"; tk.value = selectAcrossToken;
      form.appendChild(sa);
      form.appendChild(tk);
    } else {
      selectedPks().forEach((pk) => {
        const h = document.createElement("input");
        h.type = "hidden"; h.name = "selected_pks"; h.value = pk;
        form.appendChild(h);
      });
    }
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

  const batchBar = document.getElementById("dk-batch-save-bar");
  const batchCountEl = document.getElementById("dk-batch-dirty-count");
  const batchForm = document.getElementById("dk-batch-edit-form");
  function getDirtyBatchRows() {
    const dirtyRows = new Set();
    document.querySelectorAll("[data-deck-batch-input]").forEach((el) => {
      const orig = el.getAttribute("data-orig-val") || "";
      const cur = el.type === "checkbox" ? (el.checked ? "true" : "false") : String(el.value || "");
      const changed = cur !== orig;
      const td = el.closest("td");
      if (td) td.classList.toggle("is-dirty", changed);
      if (changed) dirtyRows.add(el.getAttribute("data-batch-row") || "");
    });
    return dirtyRows;
  }
  function syncBatchDirty() {
    if (!batchBar) return;
    const dirtyRows = getDirtyBatchRows();
    batchBar.hidden = dirtyRows.size === 0;
    if (batchCountEl) batchCountEl.textContent = dirtyRows.size + " row(s) changed";
  }
  if (batchBar) {
    document.addEventListener("input", (e) => { if (e.target instanceof Element && e.target.matches("[data-deck-batch-input]")) syncBatchDirty(); });
    document.addEventListener("change", (e) => { if (e.target instanceof Element && e.target.matches("[data-deck-batch-input]")) syncBatchDirty(); });
    if (batchForm) {
      batchForm.addEventListener("submit", () => {
        const dirtyRows = getDirtyBatchRows();
        document.querySelectorAll("[data-deck-batch-input]").forEach((el) => {
          const r = el.getAttribute("data-batch-row") || "";
          if (!dirtyRows.has(r)) el.disabled = true;
        });
        document.querySelectorAll("[data-batch-row-meta]").forEach((el) => {
          const r = el.getAttribute("data-batch-row-meta") || "";
          if (!dirtyRows.has(r)) el.disabled = true;
        });
      });
    }
    const discBtn = batchBar.querySelector("[data-deck-batch-discard]");
    if (discBtn) {
      discBtn.addEventListener("click", () => {
        document.querySelectorAll("[data-deck-batch-input]").forEach((el) => {
          el.disabled = false;
          const orig = el.getAttribute("data-orig-val") || "";
          if (el.type === "checkbox") el.checked = orig === "true";
          else el.value = orig;
        });
        document.querySelectorAll("[data-batch-row-meta]").forEach((el) => { el.disabled = false; });
        syncBatchDirty();
      });
    }
  }

  const filterPanel = document.getElementById("dk-filter-panel");
  function hydrateFilterFacets() {
    if (!filterPanel || filterPanel.hidden) return;
    if (filterPanel.getAttribute("data-facets-loaded") === "1") return;
    const facetsUrl = filterPanel.getAttribute("data-facets-url") || "";
    if (!facetsUrl) return;
    filterPanel.setAttribute("data-facets-loaded", "1");
    fetch(facetsUrl + (window.location.search || ""), { headers: { Accept: "application/json" } })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data || !data.facets) return;
        Object.entries(data.facets).forEach(([fieldKey, counts]) => {
          const sel = filterPanel.querySelector('select[data-facet-field="' + CSS.escape(fieldKey) + '"]');
          if (!sel || !counts) return;
          Array.from(sel.options).forEach((opt) => {
            const base = opt.getAttribute("data-facet-base");
            if (!base || !opt.value) return;
            if (Object.prototype.hasOwnProperty.call(counts, opt.value)) {
              opt.textContent = base + " (" + counts[opt.value] + ")";
            }
          });
        });
      })
      .catch(() => { filterPanel.removeAttribute("data-facets-loaded"); });
  }
  if (filterPanel && !filterPanel.hidden) hydrateFilterFacets();

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const filterToggle = t.closest('[data-deck-toggle="dk-filter-panel"]');
    if (filterToggle) {
      window.setTimeout(hydrateFilterFacets, 0);
      return;
    }

    const sortLink = t.closest("a[data-sort-col]");
    if (sortLink && e.shiftKey) {
      e.preventDefault();
      const col = sortLink.getAttribute("data-sort-col") || "";
      if (!col) return;
      const curRaw = sortLink.getAttribute("data-sort-active") || "";
      const specs = curRaw
        ? curRaw.split(",").map((s) => s.trim().split(":")).filter((p) => p[0]).map((p) => [p[0], p[1] === "asc" ? "asc" : "desc"])
        : [];
      const idx = specs.findIndex((p) => p[0] === col);
      if (idx >= 0) {
        specs[idx][1] = specs[idx][1] === "desc" ? "asc" : "desc";
      } else {
        if (specs.length >= 3) specs.shift();
        specs.push([col, "desc"]);
      }
      const nextSort = specs.map((p) => p[0] + ":" + p[1]).join(",");
      const url = new URL(window.location.href);
      url.searchParams.set("sort", nextSort);
      url.searchParams.delete("dir");
      url.searchParams.set("page", "1");
      url.searchParams.delete("after");
      url.searchParams.delete("before");
      window.location.assign(url.toString());
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
      const impactUrl = bulkBtn.getAttribute("data-impact-url") || "";
      const impactForce = bulkBtn.getAttribute("data-impact-force") === "true";
      const bulkDemoSafe = Boolean(bulkDock && bulkDock.getAttribute("data-demo-safe") === "1");
      const demoLocked = bulkBtn.getAttribute("data-demo-locked") === "1" || (bulkDemoSafe && selectAcrossActive);
      const demoLockMsg =
        bulkBtn.getAttribute("data-demo-lock-msg") ||
        (selectAcrossActive
          ? "Select-across mass actions are disabled in public Demo Safe Mode. Select individual rows on this page instead."
          : "");
      const rawFields = bulkBtn.getAttribute("data-action-fields") || "";
      let fields = [];
      if (rawFields) { try { fields = JSON.parse(rawFields); } catch (_) {} }
      const pks = selectedPks();
      const count = selectAcrossActive ? selectAcrossTotal : pks.length;
      const phrase = phraseTpl ? phraseTpl.replace("{n}", String(count)) : "";
      if (needConfirm || phrase || fields.length || impactUrl || demoLocked) {
        D.openConfirm({
          title: label,
          message: "Apply '" + label + "' to " + count.toLocaleString() + " selected record(s)?",
          phrase,
          fields,
          demoLocked,
          demoLockMsg,
          impactUrl,
          impactBody: impactUrl
            ? {
                pks: selectAcrossActive ? [] : pks,
                select_across: selectAcrossActive,
                slice_token: selectAcrossActive ? selectAcrossToken : "",
                force: impactForce,
              }
            : null,
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
    if (t.matches("[data-deck-page-size]")) {
      const opt = t.options && t.selectedIndex >= 0 ? t.options[t.selectedIndex] : null;
      const href = opt ? opt.getAttribute("data-href") : "";
      if (href) window.location.assign(href);
      return;
    }
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
