/* Flask-Deck — Forms, Dropzone, Widgets, FK Combobox, Tags, Wizard & Inlines */
(function () {
  "use strict";
  const D = window.__deck;
  if (!D) return;

  document.querySelectorAll("[data-deck-slider]").forEach((wrap) => {
    const inp = wrap.querySelector("[data-slider-input]");
    const out = wrap.querySelector("[data-slider-val]");
    const suffix = wrap.getAttribute("data-slider-suffix") || "%";
    if (inp && out) inp.addEventListener("input", () => { out.textContent = inp.value + suffix; });
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

  document.addEventListener("click", (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;

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
