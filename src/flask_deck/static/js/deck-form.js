/* Flask-Deck — Forms, Dropzone, Widgets, FK Combobox, Tags, Wizard & Inlines */
(function () {
  "use strict";
  const D = window.__deck;
  if (!D) return;

  document.querySelectorAll("[data-deck-slider]").forEach((wrap) => {
    const inp = wrap.querySelector("[data-slider-input]");
    const out = wrap.querySelector("[data-slider-val]");
    const suffix = wrap.hasAttribute("data-slider-suffix") ? (wrap.getAttribute("data-slider-suffix") || "") : "%";
    if (inp && out) inp.addEventListener("input", () => { out.textContent = inp.value + suffix; });
  });

  document.querySelectorAll("[data-color-widget]").forEach((wrap) => {
    const inp = wrap.querySelector("[data-color-input]");
    const lbl = wrap.querySelector("[data-color-label]");
    if (inp && lbl) inp.addEventListener("input", () => { lbl.textContent = inp.value; });
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

  document.querySelectorAll("[data-deck-md]").forEach((wrap) => {
    const ta = wrap.querySelector("[data-md-input]");
    const prev = wrap.querySelector("[data-md-preview]");
    if (!ta || !prev) return;
    wrap.querySelectorAll("[data-md-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const mode = btn.getAttribute("data-md-mode");
        wrap.querySelectorAll("[data-md-mode]").forEach((b) => b.classList.toggle("is-active", b === btn));
        if (mode === "preview") { D.renderSafeMarkdown(ta.value, prev); ta.hidden = true; prev.hidden = false; }
        else { ta.hidden = false; prev.hidden = true; }
      });
    });
  });

  function initFkWidgets(rootEl) {
    (rootEl || document).querySelectorAll("[data-deck-fk]").forEach((wrap) => {
      if (wrap.hasAttribute("data-fk-bound")) return;
      wrap.setAttribute("data-fk-bound", "1");
      const searchInput = wrap.querySelector("[data-fk-search]");
      const hiddenInput = wrap.querySelector("[data-fk-value]");
      const dropdown = wrap.querySelector("[data-fk-dropdown]");
      const apiUrl = wrap.getAttribute("data-fk-url") || "";
      let depSpec = null;
      try { const rawDep = wrap.getAttribute("data-dependent"); if (rawDep) depSpec = JSON.parse(rawDep); } catch (_) {}
      if (!searchInput || !hiddenInput || !dropdown) return;
      let fkAbort = null;
      let curQuery = "";
      let curPage = 1;
      let loadedItems = [];
      const isRawId = searchInput.getAttribute("data-fk-raw-id") === "1";
      const ownerForm = wrap.closest("form") || document;
      const initialOpts = Array.from(dropdown.querySelectorAll(".dk-fk-opt")).map((el) => ({
        id: el.getAttribute("data-id") || "",
        label: el.getAttribute("data-label") || "",
      }));
      wrap._dkSyncOpt = (id, label, remove) => {
        const idx = initialOpts.findIndex((o) => o.id === String(id));
        if (remove) { if (idx >= 0) initialOpts.splice(idx, 1); }
        else if (idx >= 0) initialOpts[idx].label = label;
        else initialOpts.unshift({ id: String(id), label: String(label) });
      };
      function readParentVal(name) {
        const r = ownerForm.querySelector('input[type="radio"][name="' + name + '"]:checked');
        if (r) return r.value;
        const el = ownerForm.querySelector('[name="' + name + '"]');
        if (!el || el.type === "radio") return "";
        return el.type === "checkbox" ? (el.checked ? "true" : "false") : el.value;
      }
      function renderOpts(items, hasMore) {
        dropdown.replaceChildren();
        if (!items.length) {
          const e = document.createElement("div");
          e.className = "dk-fk-opt dk-muted";
          e.textContent = D.t("No matches");
          dropdown.appendChild(e);
          return;
        }
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
        if (hasMore && apiUrl) {
          const more = document.createElement("div");
          more.className = "dk-fk-opt dk-fk-more dk-mono";
          more.textContent = D.t("Load more…");
          more.addEventListener("mousedown", (e) => {
            e.preventDefault();
            fetchRemote(curQuery, curPage + 1, true);
          });
          dropdown.appendChild(more);
        }
      }
      function fetchRemote(q, page, append) {
        if (searchInput.readOnly || isRawId) return;
        const p = page || 1;
        curQuery = q;
        if (!apiUrl) { renderOpts(initialOpts.filter((o) => o.label.toLowerCase().includes(q.toLowerCase())), false); dropdown.hidden = false; return; }
        let url = apiUrl + (apiUrl.includes("?") ? "&" : "?") + "q=" + encodeURIComponent(q) + "&page=" + p;
        if (depSpec && depSpec.parent && depSpec.filter_col) {
          const pVal = readParentVal(depSpec.parent);
          if (pVal) url += "&dep_col=" + encodeURIComponent(depSpec.filter_col) + "&dep_val=" + encodeURIComponent(pVal);
        }
        if (fkAbort) fkAbort.abort();
        fkAbort = new AbortController();
        fetch(url, { headers: { Accept: "application/json" }, signal: fkAbort.signal })
          .then((r) => (r.ok ? r.json() : { items: [], has_more: false }))
          .then((d) => {
            if (document.activeElement !== searchInput) return;
            const batch = Array.isArray(d.items) ? d.items : [];
            curPage = p;
            if (append) {
              const seen = new Set(loadedItems.map((x) => String(x.id)));
              batch.forEach((b) => { if (!seen.has(String(b.id))) { seen.add(String(b.id)); loadedItems.push(b); } });
            } else {
              loadedItems = batch;
            }
            renderOpts(loadedItems, Boolean(d.has_more));
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
        if (searchInput.readOnly || isRawId) return;
        if (depSpec && apiUrl) fetchRemote("", 1, false);
        else { loadedItems = initialOpts.slice(); curPage = Math.max(1, Math.ceil(initialOpts.length / 25)); renderOpts(loadedItems, Boolean(apiUrl && initialOpts.length >= 50)); dropdown.hidden = false; }
      });
      searchInput.addEventListener("blur", () => { window.setTimeout(() => { dropdown.hidden = true; }, 140); });
      let fkTimer = null;
      searchInput.addEventListener("input", () => {
        if (searchInput.readOnly) return;
        const q = searchInput.value.trim();
        if (isRawId) {
          hiddenInput.value = q;
          hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
          return;
        }
        if (!q && hiddenInput.value) {
          hiddenInput.value = "";
          hiddenInput.dispatchEvent(new Event("change", { bubbles: true }));
        }
        window.clearTimeout(fkTimer);
        fkTimer = window.setTimeout(() => fetchRemote(q, 1, false), 140);
      });
    });
  }
  initFkWidgets(document);

  /* ---------- Dual-Pane & Async M2M Widgets ---------- */
  function syncDualPane(dualEl) {
    const fname = dualEl.getAttribute("data-field-name");
    const selList = dualEl.querySelector("[data-dual-sel]");
    const hidHost = dualEl.querySelector("[data-dual-hidden]");
    const cntEl = dualEl.querySelector("[data-dual-count]");
    if (!selList || !hidHost || !fname) return;
    const items = Array.from(selList.querySelectorAll("[data-dual-id]"));
    hidHost.replaceChildren();
    items.forEach((btn) => {
      const inp = document.createElement("input");
      inp.type = "hidden"; inp.name = fname; inp.value = btn.getAttribute("data-dual-id") || "";
      hidHost.appendChild(inp);
    });
    if (cntEl) cntEl.textContent = String(items.length);
  }
  document.querySelectorAll("[data-deck-m2m-dual]").forEach((dual) => {
    const avList = dual.querySelector("[data-dual-avail]");
    const selList = dual.querySelector("[data-dual-sel]");
    const avF = dual.querySelector("[data-dual-avail-filter]");
    const selF = dual.querySelector("[data-dual-sel-filter]");
    const addAll = dual.querySelector("[data-dual-add-all]");
    const rmAll = dual.querySelector("[data-dual-rm-all]");
    const isRo = Boolean(addAll && addAll.disabled);
    function filterPane(list, q) {
      if (!list) return;
      const ql = (q || "").trim().toLowerCase();
      list.querySelectorAll("[data-dual-id]").forEach((b) => { b.hidden = Boolean(ql) && !(b.getAttribute("data-dual-label") || "").includes(ql); });
    }
    if (avF) avF.addEventListener("input", () => filterPane(avList, avF.value));
    if (selF) selF.addEventListener("input", () => filterPane(selList, selF.value));
    dual.addEventListener("click", (ev) => {
      if (isRo) return;
      const item = ev.target instanceof Element ? ev.target.closest(".dk-dual-item") : null;
      if (!item || !avList || !selList) return;
      const toSel = item.parentElement === avList;
      item.classList.toggle("is-selected", toSel);
      (toSel ? selList : avList).appendChild(item);
      syncDualPane(dual);
      dual.dispatchEvent(new Event("change", { bubbles: true }));
    });
    if (addAll && avList && selList) addAll.addEventListener("click", () => {
      Array.from(avList.querySelectorAll(".dk-dual-item")).filter((b) => !b.hidden).forEach((b) => { b.classList.add("is-selected"); selList.appendChild(b); });
      syncDualPane(dual);
      dual.dispatchEvent(new Event("change", { bubbles: true }));
    });
    if (rmAll && avList && selList) rmAll.addEventListener("click", () => {
      Array.from(selList.querySelectorAll(".dk-dual-item")).filter((b) => !b.hidden).forEach((b) => { b.classList.remove("is-selected"); avList.appendChild(b); });
      syncDualPane(dual);
      dual.dispatchEvent(new Event("change", { bubbles: true }));
    });
  });

  function addAsyncM2mChip(wrap, id, label) {
    const fname = wrap.getAttribute("data-field-name");
    const host = wrap.querySelector("[data-async-chips]");
    const cnt = wrap.querySelector("[data-async-count]");
    if (!fname || !host) return;
    if (host.querySelector('[data-async-chip="' + CSS.escape(String(id)) + '"]')) return;
    const chip = document.createElement("span");
    chip.className = "dk-filter-chip";
    chip.setAttribute("data-async-chip", String(id));
    const sp = document.createElement("span"); sp.textContent = label;
    const rm = document.createElement("button"); rm.type = "button"; rm.className = "dk-subtle"; rm.setAttribute("data-async-rm", String(id)); rm.textContent = "×";
    const hid = document.createElement("input"); hid.type = "hidden"; hid.name = fname; hid.value = String(id);
    chip.appendChild(sp); chip.appendChild(rm); chip.appendChild(hid);
    host.appendChild(chip);
    if (cnt) cnt.textContent = host.querySelectorAll("[data-async-chip]").length + " selected";
    wrap.dispatchEvent(new Event("change", { bubbles: true }));
  }
  document.querySelectorAll("[data-deck-m2m-async]").forEach((wrap) => {
    const inp = wrap.querySelector("[data-async-search]");
    const dd = wrap.querySelector("[data-async-dropdown]");
    const url = wrap.getAttribute("data-search-url") || "";
    const host = wrap.querySelector("[data-async-chips]");
    const cnt = wrap.querySelector("[data-async-count]");
    let abortCtrl = null;
    let timer = null;
    wrap.addEventListener("click", (ev) => {
      const rmBtn = ev.target instanceof Element ? ev.target.closest("[data-async-rm]") : null;
      if (rmBtn && host) {
        rmBtn.closest("[data-async-chip]")?.remove();
        if (cnt) cnt.textContent = host.querySelectorAll("[data-async-chip]").length + " selected";
        wrap.dispatchEvent(new Event("change", { bubbles: true }));
      }
    });
    if (!inp || !dd || inp.readOnly) return;
    let curPage = 1;
    let curQ = "";
    let accItems = [];
    function renderAsyncList(items, hasMore) {
      dd.replaceChildren();
      if (!items.length) { const em = document.createElement("div"); em.className = "dk-fk-opt dk-muted"; em.textContent = D.t("No matches"); dd.appendChild(em); }
      else items.forEach((it) => {
        const row = document.createElement("div"); row.className = "dk-fk-opt";
        const s1 = document.createElement("span"); s1.textContent = it.label;
        const s2 = document.createElement("span"); s2.className = "dk-mono dk-subtle"; s2.textContent = "#" + it.id;
        row.appendChild(s1); row.appendChild(s2);
        row.addEventListener("mousedown", (e) => { e.preventDefault(); addAsyncM2mChip(wrap, it.id, it.label); inp.value = ""; dd.hidden = true; });
        dd.appendChild(row);
      });
      if (hasMore) {
        const more = document.createElement("div");
        more.className = "dk-fk-opt dk-fk-more dk-mono";
        more.textContent = D.t("Load more…");
        more.addEventListener("mousedown", (e) => { e.preventDefault(); fetchOpts(curQ, curPage + 1, true); });
        dd.appendChild(more);
      }
      dd.hidden = false;
    }
    function fetchOpts(q, page, append) {
      if (!url) return;
      const p = page || 1;
      curQ = q;
      if (abortCtrl) abortCtrl.abort();
      abortCtrl = new AbortController();
      fetch(url + (url.includes("?") ? "&" : "?") + "q=" + encodeURIComponent(q) + "&page=" + p, { headers: { Accept: "application/json" }, signal: abortCtrl.signal })
        .then((r) => (r.ok ? r.json() : { items: [], has_more: false }))
        .then((d) => {
          if (document.activeElement !== inp) return;
          const batch = Array.isArray(d.items) ? d.items : [];
          curPage = p;
          if (append) {
            const seen = new Set(accItems.map((x) => String(x.id)));
            batch.forEach((b) => { if (!seen.has(String(b.id))) { seen.add(String(b.id)); accItems.push(b); } });
          } else {
            accItems = batch;
          }
          renderAsyncList(accItems, Boolean(d.has_more));
        })
        .catch(() => {});
    }
    inp.addEventListener("focus", () => fetchOpts(inp.value.trim(), 1, false));
    inp.addEventListener("blur", () => { window.setTimeout(() => { dd.hidden = true; }, 140); });
    inp.addEventListener("input", () => { window.clearTimeout(timer); timer = window.setTimeout(() => fetchOpts(inp.value.trim(), 1, false), 140); });
  });

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
        D.showToast("Browser blocked drag-and-drop; use Choose File instead.", "warn");
        return;
      }
      handleFile(file);
    });
  });

  document.querySelectorAll("[data-deck-tags]").forEach((wrap) => {
    const hid = wrap.querySelector("[data-tags-hidden]");
    const host = wrap.querySelector("[data-tags-chips]");
    const inp = wrap.querySelector("[data-tags-input]");
    if (!hid || !host) return;
    const isRo = !inp || inp.readOnly || inp.disabled;
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

  function toSlug(raw) {
    const trMap = { "ğ": "g", "Ğ": "g", "ş": "s", "Ş": "s", "ı": "i", "İ": "i", "ö": "o", "Ö": "o", "ü": "u", "Ü": "u", "ç": "c", "Ç": "c" };
    return String(raw || "")
      .replace(/[ğĞşŞıİöÖüÜçÇ]/g, (ch) => trMap[ch] || ch)
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  let activeRelTarget = null;
  const formRoot = document.querySelector("[data-deck-form-root]");
  if (formRoot) {
    let isDirty = false;
    const dirtyBadge = formRoot.querySelector("[data-deck-dirty-badge]");
    const markDirty = () => {
      if (!isDirty) { isDirty = true; if (dirtyBadge) dirtyBadge.hidden = false; }
    };
    window.addEventListener("beforeunload", (ev) => {
      if (isDirty) { ev.preventDefault(); ev.returnValue = ""; }
    });
    formRoot.addEventListener("submit", () => { isDirty = false; });

    formRoot.querySelectorAll("[data-prepopulate-from]").forEach((tgt) => {
      if (tgt.readOnly || tgt.disabled) return;
      let sources = [];
      try { sources = JSON.parse(tgt.getAttribute("data-prepopulate-from") || "[]"); } catch (_) {}
      if (!Array.isArray(sources) || !sources.length) return;
      let touched = Boolean(String(tgt.value || "").trim());
      tgt.addEventListener("input", () => { touched = true; });
      sources.forEach((srcName) => {
        const srcEl = formRoot.querySelector('[name="' + srcName + '"]');
        if (srcEl) {
          srcEl.addEventListener("input", () => {
            if (touched) return;
            const joined = sources.map((n) => (formRoot.querySelector('[name="' + n + '"]')?.value || "").trim()).filter(Boolean).join(" ");
            tgt.value = toSlug(joined);
          });
        }
      });
    });

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
    formRoot.addEventListener("change", () => { markDirty(); evalShowWhen(); });
    formRoot.addEventListener("input", () => { markDirty(); evalShowWhen(); });
    evalShowWhen();

    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "s" && !D.hasOpenOverlay()) {
        e.preventDefault();
        const kind = e.shiftKey ? "continue" : "save";
        const btn = formRoot.querySelector('[data-save-btn="' + kind + '"]') || formRoot.querySelector('[data-save-btn="save"]');
        isDirty = false;
        if (btn) btn.click(); else formRoot.submit();
      }
    });

    const panels = Array.from(formRoot.querySelectorAll("[data-deck-form-panel]"));
    const tabBtns = Array.from(formRoot.querySelectorAll("[data-deck-form-tab]"));
    const isWizard = formRoot.hasAttribute("data-deck-wizard");
    let showPanelAt = null;

    if (isWizard && panels.length) {
      const steps = Array.from(formRoot.querySelectorAll("[data-wiz-idx]"));
      const prevBtn = formRoot.querySelector("[data-wiz-prev]");
      const nextBtn = formRoot.querySelector("[data-wiz-next]");
      const subBtn = formRoot.querySelector("[data-wiz-submit]");
      const contBtn = formRoot.querySelector('[data-save-btn="continue"]');
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
        formRoot.querySelectorAll("[data-wiz-submit]").forEach((b) => { b.hidden = curStep < panels.length - 1; });
        if (subBtn) subBtn.hidden = curStep < panels.length - 1;
        if (contBtn) contBtn.hidden = curStep < panels.length - 1;
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

  function loadLookupUrl(url) {
    const drawerBody = document.getElementById("dk-drawer-body");
    if (!drawerBody || !url) return;
    fetch(url, { headers: { "X-Requested-With": "Flask-Deck" } })
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error("fail"))))
      .then((html) => {
        const doc = new DOMParser().parseFromString(html, "text/html");
        drawerBody.replaceChildren(...Array.from(doc.body.childNodes));
      })
      .catch(() => D.showToast(D.t("Network error"), "danger"));
  }

  document.addEventListener("submit", (e) => {
    const lf = e.target instanceof Element ? e.target.closest("[data-deck-lookup-form]") : null;
    if (lf) {
      e.preventDefault();
      const base = lf.getAttribute("action") || "";
      const qInp = lf.querySelector('input[name="q"]');
      const qVal = qInp ? qInp.value.trim() : "";
      loadLookupUrl(base + (base.includes("?") ? "&" : "?") + "q=" + encodeURIComponent(qVal) + "&page=1");
      return;
    }
    const qf = e.target instanceof Element ? e.target.closest("[data-deck-quick-form]") : null;
    if (!qf) return;
    e.preventDefault();
    const drawerBody = document.getElementById("dk-drawer-body");
    fetch(qf.action, { method: "POST", body: new FormData(qf), headers: { "X-Requested-With": "Flask-Deck", "X-Deck-CSRFToken": D.CSRF } })
      .then(async (r) => {
        const ct = r.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          const d = await r.json();
          if (!r.ok || !d.ok) { D.showToast(d.error || D.t("Save failed"), "danger"); return; }
          if (activeRelTarget && activeRelTarget.fkInputId) {
            const srch = document.getElementById(activeRelTarget.fkInputId);
            const wrap = srch && srch.closest("[data-deck-fk]");
            const hid = wrap && wrap.querySelector("[data-fk-value]");
            if (wrap && typeof wrap._dkSyncOpt === "function") wrap._dkSyncOpt(d.id, d.label, false);
            if (hid) { hid.value = d.id; hid.dispatchEvent(new Event("change", { bubbles: true })); }
            if (srch) srch.value = srch.getAttribute("data-fk-raw-id") === "1" ? d.id : d.label;
          } else if (activeRelTarget && activeRelTarget.m2mField) {
            const fname = activeRelTarget.m2mField;
            const dual = document.querySelector('[data-deck-m2m-dual][data-field-name="' + fname + '"]');
            const asyncEl = document.querySelector('[data-deck-m2m-async][data-field-name="' + fname + '"]');
            const pillsEl = document.querySelector('[data-deck-m2m][data-field-name="' + fname + '"]');
            if (dual) {
              const selList = dual.querySelector("[data-dual-sel]");
              if (selList) {
                const btn = document.createElement("button");
                btn.type = "button"; btn.className = "dk-dual-item is-selected";
                btn.setAttribute("data-dual-id", d.id); btn.setAttribute("data-dual-label", String(d.label).toLowerCase());
                btn.textContent = d.label;
                selList.appendChild(btn);
                syncDualPane(dual);
              }
            } else if (asyncEl) {
              addAsyncM2mChip(asyncEl, d.id, d.label);
            } else if (pillsEl) {
              const box = pillsEl.querySelector("[data-m2m-pills]");
              if (box) {
                const lbl = document.createElement("label"); lbl.className = "dk-m2m-pill"; lbl.setAttribute("data-m2m-item", String(d.label).toLowerCase());
                const cb = document.createElement("input"); cb.type = "checkbox"; cb.name = fname; cb.value = d.id; cb.checked = true; cb.setAttribute("data-m2m-check", "");
                const sp = document.createElement("span"); sp.textContent = d.label;
                lbl.appendChild(cb); lbl.appendChild(sp); box.appendChild(lbl);
                pillsEl.dispatchEvent(new Event("change", { bubbles: true }));
              }
            }
          }
          if (typeof D.closeDrawer === "function") D.closeDrawer();
          D.showToast("Saved: " + d.label, "ok");
        } else {
          const html = await r.text();
          if (drawerBody) {
            const doc = new DOMParser().parseFromString(html, "text/html");
            drawerBody.replaceChildren(...Array.from(doc.body.childNodes));
          }
        }
      })
      .catch(() => D.showToast("Network error saving related record", "danger"));
  });

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

    const pad2 = (n) => String(n).padStart(2, "0");
    function tzParts(dateObj) {
      const tzMeta = document.querySelector('meta[name="deck-tz"]');
      const tz = tzMeta ? tzMeta.content.trim() : "";
      if (tz && typeof Intl !== "undefined" && Intl.DateTimeFormat) {
        try {
          const parts = {};
          new Intl.DateTimeFormat("en-CA", {
            timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
          }).formatToParts(dateObj).forEach((p) => { parts[p.type] = p.value; });
          const hr = parts.hour === "24" ? "00" : parts.hour;
          if (parts.year && parts.month && parts.day && hr && parts.minute) {
            return { y: parts.year, mo: parts.month, d: parts.day, h: hr, mi: parts.minute };
          }
        } catch (_) {}
      }
      return { y: String(dateObj.getFullYear()), mo: pad2(dateObj.getMonth() + 1), d: pad2(dateObj.getDate()), h: pad2(dateObj.getHours()), mi: pad2(dateObj.getMinutes()) };
    }
    const todayBtn = t.closest("[data-deck-set-today]");
    if (todayBtn) {
      const inp = document.getElementById(todayBtn.getAttribute("data-deck-set-today") || "");
      if (inp && !inp.readOnly && !inp.disabled) {
        const p = tzParts(new Date());
        inp.value = p.y + "-" + p.mo + "-" + p.d;
        inp.dispatchEvent(new Event("input", { bubbles: true }));
        inp.dispatchEvent(new Event("change", { bubbles: true }));
      }
      return;
    }

    const nowBtn = t.closest("[data-deck-set-now]");
    if (nowBtn) {
      const inp = document.getElementById(nowBtn.getAttribute("data-deck-set-now") || "");
      if (inp && !inp.readOnly && !inp.disabled) {
        const p = tzParts(new Date());
        const hm = p.h + ":" + p.mi;
        inp.value = nowBtn.getAttribute("data-now-kind") === "time"
          ? hm
          : p.y + "-" + p.mo + "-" + p.d + "T" + hm;
        inp.dispatchEvent(new Event("input", { bubbles: true }));
        inp.dispatchEvent(new Event("change", { bubbles: true }));
      }
      return;
    }

    const relLookup = t.closest("[data-deck-rel-lookup]");
    if (relLookup) {
      const base = relLookup.getAttribute("data-deck-rel-lookup") || "";
      const targetId = relLookup.getAttribute("data-rel-target") || "";
      const title = relLookup.getAttribute("data-rel-title") || D.t("Lookup");
      if (base) {
        let url = base + (base.includes("?") ? "&" : "?") + "target_field=" + encodeURIComponent(targetId);
        const srchEl = document.getElementById(targetId);
        const fkWrap = srchEl && srchEl.closest("[data-deck-fk]");
        if (fkWrap) {
          try {
            const dep = JSON.parse(fkWrap.getAttribute("data-dependent") || "null");
            const fm = fkWrap.closest("form") || document;
            if (dep && dep.parent && dep.filter_col) {
              const pel = fm.querySelector('[name="' + dep.parent + '"]');
              const pv = pel ? (pel.type === "checkbox" ? (pel.checked ? "true" : "false") : pel.value) : "";
              if (pv) url += "&dep_col=" + encodeURIComponent(dep.filter_col) + "&dep_val=" + encodeURIComponent(pv);
            }
          } catch (_) {}
        }
        D.openDrawer(url, title);
      }
      return;
    }

    const lookupPage = t.closest("[data-deck-lookup-page]");
    if (lookupPage) {
      const root = lookupPage.closest("[data-deck-lookup-root]");
      const base = root ? (root.getAttribute("data-lookup-url") || "") : "";
      const pg = lookupPage.getAttribute("data-deck-lookup-page") || "1";
      const q = lookupPage.getAttribute("data-lookup-q") || "";
      if (base) loadLookupUrl(base + (base.includes("?") ? "&" : "?") + "q=" + encodeURIComponent(q) + "&page=" + encodeURIComponent(pg));
      return;
    }

    const lookupPick = t.closest("[data-deck-lookup-pick]");
    if (lookupPick) {
      const targetId = lookupPick.getAttribute("data-target-field") || "";
      const pk = lookupPick.getAttribute("data-pk") || "";
      const lbl = lookupPick.getAttribute("data-label") || pk;
      const srch = document.getElementById(targetId);
      const wrap = srch && srch.closest("[data-deck-fk]");
      const hid = wrap && wrap.querySelector("[data-fk-value]");
      if (hid) { hid.value = pk; hid.dispatchEvent(new Event("change", { bubbles: true })); }
      if (srch) srch.value = srch.getAttribute("data-fk-raw-id") === "1" ? pk : lbl;
      if (typeof D.closeDrawer === "function") D.closeDrawer();
      D.showToast(D.t("Select") + ": " + lbl, "ok");
      return;
    }

    const relDel = t.closest("[data-deck-rel-del]");
    if (relDel) {
      const targetId = relDel.getAttribute("data-rel-target") || "";
      const srch = document.getElementById(targetId);
      const wrap = srch && srch.closest("[data-deck-fk]");
      const hid = wrap && wrap.querySelector("[data-fk-value]");
      const pk = hid ? String(hid.value || "").trim() : "";
      if (!pk) { D.showToast("Select a related record first", "warn"); return; }
      const tpl = relDel.getAttribute("data-deck-rel-del") || "";
      const delUrl = tpl.replace("__PK__", encodeURIComponent(pk));
      const impactUrl = relDel.getAttribute("data-impact-url") || "";
      const lbl = (srch && srch.value) || pk;
      D.openConfirm({
        title: relDel.getAttribute("data-rel-title") || D.t("Delete Related"),
        message: "Delete related record '" + lbl + "'?",
        impactUrl,
        impactBody: impactUrl ? { pks: [pk], force: false } : null,
        onConfirm: () => {
          fetch(delUrl, {
            method: "POST",
            headers: { "X-Deck-CSRFToken": D.CSRF, "X-Requested-With": "Flask-Deck", Accept: "application/json" },
          })
            .then((r) => r.json().then((d) => ({ ok: r.ok, data: d })))
            .then(({ ok, data }) => {
              if (!ok || !data.ok) { D.showToast(data.error || D.t("Update failed"), "danger"); return; }
              if (wrap && typeof wrap._dkSyncOpt === "function") wrap._dkSyncOpt(pk, "", true);
              if (hid) { hid.value = ""; hid.dispatchEvent(new Event("change", { bubbles: true })); }
              if (srch) srch.value = "";
              D.showToast(D.t("Delete") + ": " + (data.label || lbl), "ok");
            })
            .catch(() => D.showToast(D.t("Network error"), "danger"));
        },
      });
      return;
    }

    const relAdd = t.closest("[data-deck-rel-add]");
    if (relAdd) {
      const url = relAdd.getAttribute("data-deck-rel-add");
      const title = relAdd.getAttribute("data-rel-title") || "New Record";
      activeRelTarget = {
        fkInputId: relAdd.getAttribute("data-rel-target") || "",
        m2mField: relAdd.getAttribute("data-rel-m2m-target") || "",
      };
      if (url) D.openDrawer(url, title);
      return;
    }

    const relEditOrPeek = t.closest("[data-deck-rel-edit], [data-deck-rel-peek]");
    if (relEditOrPeek) {
      const targetId = relEditOrPeek.getAttribute("data-rel-target") || "";
      const srch = document.getElementById(targetId);
      const wrap = srch && srch.closest("[data-deck-fk]");
      const hid = wrap && wrap.querySelector("[data-fk-value]");
      const pk = hid ? String(hid.value || "").trim() : "";
      if (!pk) { D.showToast("Select a related record first", "warn"); return; }
      const tpl = relEditOrPeek.getAttribute("data-deck-rel-edit") || relEditOrPeek.getAttribute("data-deck-rel-peek") || "";
      const url = tpl.replace("__PK__", encodeURIComponent(pk));
      activeRelTarget = { fkInputId: targetId, m2mField: "" };
      D.openDrawer(url, relEditOrPeek.getAttribute("data-rel-title") || "Related Record");
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

    const addInlineBtn = t.closest("[data-deck-add-inline]");
    if (addInlineBtn) {
      const slug = addInlineBtn.getAttribute("data-deck-add-inline");
      const tpl = document.querySelector('template[data-inline-template="' + slug + '"]');
      const host = document.querySelector('[data-inline-body="' + slug + '"]');
      if (tpl && host) {
        const maxRows = Number(host.getAttribute("data-max-rows") || "0");
        const activeRows = Array.from(host.querySelectorAll("[data-inline-row]")).filter((r) => {
          const df = r.querySelector("[data-inline-del-flag]");
          return !df || df.value !== "1";
        }).length;
        if (maxRows > 0 && activeRows >= maxRows) {
          D.showToast("Maximum " + maxRows + " rows allowed", "warn");
          return;
        }
        const nextIdx = Number(host.getAttribute("data-next-index") || "0");
        host.setAttribute("data-next-index", String(nextIdx + 1));
        const frag = tpl.content.cloneNode(true);
        frag.querySelectorAll("[name]").forEach((el) => el.setAttribute("name", el.getAttribute("name").replace("__INDEX__", String(nextIdx))));
        frag.querySelectorAll("[id]").forEach((el) => el.setAttribute("id", el.getAttribute("id").replace("__INDEX__", String(nextIdx))));
        frag.querySelectorAll("[data-rel-target]").forEach((el) => el.setAttribute("data-rel-target", el.getAttribute("data-rel-target").replace("__INDEX__", String(nextIdx))));
        host.appendChild(frag);
        initFkWidgets(host);
        host.dispatchEvent(new Event("change", { bubbles: true }));
      }
      return;
    }

    const delInlineBtn = t.closest("[data-deck-del-inline]");
    if (delInlineBtn) {
      const row = delInlineBtn.closest("[data-inline-row]") || delInlineBtn.closest("tr");
      if (!row) return;
      const delInput = row.querySelector("[data-inline-del-flag]");
      if (delInput) {
        const isMarked = delInput.value === "1";
        delInput.value = isMarked ? "0" : "1";
        row.classList.toggle("dk-inline-deleted", !isMarked);
        row.querySelectorAll("input:not([type='hidden']), select, textarea").forEach((el) => { el.disabled = !isMarked; });
        delInput.dispatchEvent(new Event("change", { bubbles: true }));
      } else {
        const host = row.parentElement;
        row.remove();
        if (host) host.dispatchEvent(new Event("change", { bubbles: true }));
      }
      return;
    }

    const prettyBtn = t.closest("[data-deck-pretty-json]");
    if (prettyBtn) {
      const ta = document.getElementById(prettyBtn.getAttribute("data-deck-pretty-json"));
      if (ta) { try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); D.showToast("Formatted JSON", "ok"); } catch (_) { D.showToast("Invalid JSON syntax", "danger"); } }
    }
  });

  document.addEventListener("change", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    if (t.matches('.dk-switch input[type="checkbox"]')) {
      const row = t.closest(".dk-switch-row");
      const lbl = row && row.querySelector("[data-switch-label]");
      if (lbl) lbl.textContent = t.checked ? "Enabled" : "Disabled";
    }
  });
})();
