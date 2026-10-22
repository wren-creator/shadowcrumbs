"use strict";

// Sources page. Same rule as the rest of the UI: everything shown is set with textContent, never as markup.
// The helpers below are copies of the ones in app.js, so this page does not depend on that file.

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(typeof data.detail === "string" ? data.detail : `${res.status} ${res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function rememberedName() {
  try { return localStorage.getItem("sc-operator") || ""; } catch { return ""; }
}
function rememberName(name) {
  try { if (name.trim()) localStorage.setItem("sc-operator", name.trim()); } catch { /* not remembered, still works */ }
}

const state = {
  snap: null,          // /api/custom-sources
  categories: [],
  engagements: [],
  editing: null,       // slug being edited, or null for a new source
  draft: null,         // what is in the form
  preview: null,
  notice: null,        // { kind: "ok" | "error" | "warn", text, reload }
  importResult: null,
};

const blank = () => ({
  label: "", description: "", category: "tech", needs: ["domain"], queries: "", keywords: "",
  only_on_domain: false, extractor: "title", confidence: 50, author: rememberedName(), engagement: "",
});

const lines = (text) => text.split("\n").map((l) => l.trim()).filter(Boolean);
const words = (text) => text.split(",").map((w) => w.trim()).filter(Boolean);
const catLabel = (key) => (state.categories.find((c) => c.key === key) || { label: key }).label;

// the form ------------------------------------------------------------

function field(label, hint, control) {
  return el("label", { class: "fld" }, el("span", { class: "fl" }, label), control, hint && el("span", { class: "hint" }, hint));
}

function summaryLine() {
  const d = state.draft;
  const qs = lines(d.queries);
  const seconds = Math.round(qs.length * (state.snap.search_delay || 0));
  const bad = qs.filter((q) => /[{}]/.test(q.replace(/\{(domain|d|company)\}/g, "")));
  const used = new Set();
  for (const q of qs) {
    if (/\{(domain|d)\}/.test(q)) used.add("domain");
    if (/\{company\}/.test(q)) used.add("company");
  }
  const missing = [...used].filter((u) => !d.needs.includes(u));
  const parts = [`${qs.length} search${qs.length === 1 ? "" : "es"}`];
  if (qs.length) parts.push(`about ${seconds} seconds per run at the current pace`);
  let cls = "dim";
  if (qs.length > state.snap.limits.queries) { parts.push(`too many, the limit is ${state.snap.limits.queries}`); cls = "error"; }
  if (bad.length) { parts.push("a placeholder looks wrong, use only {domain} and {company}"); cls = "error"; }
  if (missing.length) { parts.push(`you use {${missing[0]}} so tick it under "What it needs"`); cls = "error"; }
  return el("div", { class: `${cls} live`, id: "live" }, parts.join(", "));
}

function insertAtCursor(area, text) {
  const start = area.selectionStart ?? area.value.length;
  const end = area.selectionEnd ?? area.value.length;
  area.value = area.value.slice(0, start) + text + area.value.slice(end);
  area.focus();
  area.setSelectionRange(start + text.length, start + text.length);
  area.dispatchEvent(new Event("input"));
}

function renderForm() {
  const d = state.draft;
  const host = $("#form-card");
  const set = (key) => (ev) => { d[key] = ev.target.value; };

  const label = el("input", { type: "text", name: "label", maxlength: "60", required: true, value: d.label, placeholder: "Careers page tech hints", oninput: set("label") });
  const description = el("input", { type: "text", name: "description", maxlength: "200", value: d.description, placeholder: "What this finds, in a few words", oninput: set("description") });
  const category = el("select", { name: "category", onchange: set("category") },
    ...state.categories.map((c) => el("option", { value: c.key, selected: c.key === d.category }, c.label)));

  const needBox = (key, text) => el("label", { class: "check" },
    el("input", {
      type: "checkbox", name: `need-${key}`, checked: d.needs.includes(key),
      onchange: (ev) => {
        d.needs = ev.target.checked ? [...new Set([...d.needs, key])] : d.needs.filter((n) => n !== key);
        if (!d.needs.includes("domain")) { d.only_on_domain = false; if (["email", "hostname"].includes(d.extractor)) d.extractor = "title"; }
        renderForm();
      },
    }), ` ${text}`);

  const queries = el("textarea", {
    name: "queries", rows: "5", spellcheck: "false", placeholder: 'site:{domain} careers\n"{company}" "experience with"',
    oninput: (ev) => { d.queries = ev.target.value; $("#live").replaceWith(summaryLine()); },
  });
  queries.value = d.queries;
  const chip = (text) => el("button", { type: "button", class: "chip", onclick: () => insertAtCursor(queries, text) }, text);

  const keywords = el("input", { type: "text", name: "keywords", value: d.keywords, placeholder: "login, admin, vpn", oninput: set("keywords") });
  const hasDomain = d.needs.includes("domain");
  const onDomain = el("input", { type: "checkbox", name: "only_on_domain", checked: d.only_on_domain, disabled: !hasDomain, onchange: (ev) => { d.only_on_domain = ev.target.checked; } });
  const extractor = el("select", { name: "extractor", onchange: set("extractor") },
    ...Object.entries(state.snap.extractors).map(([k, text]) =>
      el("option", { value: k, selected: k === d.extractor, disabled: !hasDomain && ["email", "hostname"].includes(k) }, text)));
  const confidence = el("input", { type: "number", name: "confidence", min: "0", max: "100", value: String(d.confidence), oninput: (ev) => { d.confidence = ev.target.value; } });
  const author = el("input", { type: "text", name: "author", maxlength: "80", required: true, value: d.author, placeholder: "Who is adding this", oninput: set("author") });

  const engagement = el("select", { name: "engagement", "aria-label": "Engagement to preview against", onchange: set("engagement") },
    el("option", { value: "" }, "(no engagement, show the raw searches)"),
    ...state.engagements.map((e) => el("option", { value: e.slug, selected: e.slug === d.engagement }, e.name)));

  host.replaceChildren(
    el("h3", {}, state.editing ? `Editing ${state.editing}` : "Add a data point"),
    el("form", { id: "source-form", onsubmit: save },
      field("Name", "Shown on this page and in the dashboard.", label),
      field("What it finds", null, description),
      field("File the findings under", "Which tab of the results they land in.", category),
      el("div", { class: "fld" }, el("span", { class: "fl" }, "What it needs from the target"),
        el("div", { class: "checks" }, needBox("domain", "the domain, like acme.com"), needBox("company", "the company name")),
        el("span", { class: "hint" }, "If the target does not have everything ticked here, the source is skipped for it, with the reason in the run history.")),
      el("div", { class: "fld" }, el("span", { class: "fl" }, "Searches, one per line"),
        queries,
        el("div", { class: "chips" }, "Click to insert: ", chip("{domain}"), chip("{company}"), chip("site:"), chip("filetype:pdf"), chip('"exact phrase"'), chip(" OR ")),
        summaryLine(),
        el("span", { class: "hint" }, "These go to a search engine, so do not put client secrets or internal code names in them. Search operators like site:, filetype: and quotes all work.")),
      field("Only keep results that mention any of", "Optional. Words, separated by commas. Leave empty to keep everything.", keywords),
      el("label", { class: "check" }, onDomain, " Only keep results that are on the target's own domain"),
      field("Record each result as", null, extractor),
      field("Confidence, 0 to 100", "How sure you are a result is really theirs. 50 is a fair default, raise it for tight searches.", confidence),
      field("Your name", "Saved with the source so the team knows who to ask.", author),
      el("div", { class: "toolbar" },
        el("button", { class: "btn primary", type: "submit" }, state.editing ? "Save changes" : "Save source"),
        state.editing && el("button", { class: "btn ghost", type: "button", onclick: cancelEdit }, "Cancel"),
        el("span", { class: "spacer" }),
        engagement, el("button", { class: "btn", type: "button", onclick: showPreview }, "Show the searches")),
      state.notice && el("div", { class: state.notice.kind === "ok" ? "ok" : state.notice.kind === "warn" ? "warn" : "error", role: "alert" },
        state.notice.text, state.notice.reload && el("button", { class: "btn small", type: "button", onclick: () => load() }, "Reload")),
      previewBlock()));
}

function previewBlock() {
  const p = state.preview;
  if (!p) return null;
  return el("div", { class: "preview", id: "preview" },
    el("div", { class: "dim" }, p.queries.length
      ? `It would send ${p.queries.length} search${p.queries.length === 1 ? "" : "es"}, about ${p.seconds} seconds at the current pace:`
      : "It would send nothing for this target."),
    el("ul", {}, ...p.queries.map((q) => el("li", {}, el("code", {}, q)))),
    ...p.dropped.map((x) => el("div", { class: "warn" }, `Skipped ${x.query}: ${x.reason}.`)));
}

function body() {
  const d = state.draft;
  return {
    label: d.label, description: d.description, category: d.category, needs: d.needs,
    queries: lines(d.queries), keywords: words(d.keywords), only_on_domain: d.only_on_domain,
    extractor: d.extractor, confidence: Number(d.confidence), author: d.author,
  };
}

async function showPreview() {
  state.notice = null;
  try {
    state.preview = await api("/api/custom-sources/preview", { method: "POST", body: { ...body(), engagement: state.draft.engagement || null } });
  } catch (err) {
    state.preview = null;
    state.notice = { kind: "error", text: err.message };
  }
  renderForm();
}

async function save(ev) {
  ev.preventDefault();
  state.notice = null;
  const payload = { ...body(), expected_revision: state.snap.revision };
  try {
    const saved = state.editing
      ? await api(`/api/custom-sources/${encodeURIComponent(state.editing)}`, { method: "PUT", body: payload })
      : await api("/api/custom-sources", { method: "POST", body: payload });
    rememberName(state.draft.author);
    const author = state.draft.author;
    state.editing = null;
    state.preview = null;
    state.draft = { ...blank(), author };
    await load({ ok: `Saved as ${saved.plugin}. It is already in the dashboard's search sources, ready to run.` });
  } catch (err) {
    state.notice = { kind: "error", text: err.message, reload: err.status === 409 };
    renderForm();
  }
}

function cancelEdit() {
  state.editing = null;
  state.preview = null;
  state.notice = null;
  state.draft = blank();
  renderForm();
}

function edit(s) {
  state.editing = s.slug;
  state.preview = null;
  state.notice = null;
  state.draft = {
    label: s.label, description: s.description, category: s.category, needs: [...s.needs], queries: s.queries.join("\n"),
    keywords: s.keywords.join(", "), only_on_domain: s.only_on_domain, extractor: s.extractor, confidence: s.confidence,
    author: rememberedName() || s.author, engagement: "",
  };
  renderForm();
  $("#form-card").scrollIntoView({ behavior: "smooth", block: "start" });
}

// the list ------------------------------------------------------------

async function remove(s) {
  const name = state.draft.author || rememberedName();
  if (!name.trim()) {
    state.notice = { kind: "error", text: "Put your name in the form first, deleting is recorded with it." };
    renderForm();
    return;
  }
  if (!confirm(`Delete "${s.label}"? Findings it already made stay, new runs will not have it.`)) return;
  try {
    await api(`/api/custom-sources/${encodeURIComponent(s.slug)}?author=${encodeURIComponent(name)}&expected_revision=${state.snap.revision}`, { method: "DELETE" });
    if (state.editing === s.slug) cancelEdit();
    await load({ ok: `Deleted ${s.label}.` });
  } catch (err) {
    state.notice = { kind: "error", text: err.message, reload: err.status === 409 };
    renderForm();
  }
}

function card(s) {
  return el("div", { class: "src-card" },
    el("div", { class: "controls" },
      el("h3", {}, s.label), el("code", { class: "dim" }, `custom_${s.slug}`),
      el("span", { class: "spacer" }),
      el("button", { class: "btn small", onclick: () => edit(s) }, "Edit"),
      el("button", { class: "btn small danger", onclick: () => remove(s) }, "Delete")),
    el("div", {}, s.description),
    el("div", { class: "dim" },
      `Files under ${catLabel(s.category)}. Needs ${s.needs.join(" and ")}. Records the ${s.extractor}. Confidence ${s.confidence}.` +
      (s.only_on_domain ? " Only the target's own domain." : "") + (s.keywords.length ? ` Keeps results mentioning: ${s.keywords.join(", ")}.` : "")),
    el("details", {}, el("summary", {}, `${s.queries.length} search${s.queries.length === 1 ? "" : "es"}`),
      el("ul", {}, ...s.queries.map((q) => el("li", {}, el("code", {}, q))))),
    el("div", { class: "dim" }, `Added by ${s.author}, last changed ${s.updated_at || "(time not recorded)"} UTC`));
}

function renderList() {
  const snap = state.snap;
  const importInput = el("input", { type: "file", accept: ".json,application/json", id: "import-file", "aria-label": "Sources file to import" });
  const mode = el("select", { id: "import-mode", "aria-label": "If a name already exists" },
    el("option", { value: "skip" }, "skip ones I already have"),
    el("option", { value: "overwrite" }, "overwrite ones I already have"),
    el("option", { value: "rename" }, "keep both, rename the new one"));
  $("#list-card").replaceChildren(
    el("div", { class: "controls" }, el("h3", {}, `Your team's sources (${snap.sources.length})`), el("span", { class: "spacer" }),
      el("a", { class: "btn small", href: "/api/custom-sources/export", download: true }, "Export all")),
    ...snap.problems.map((p) => el("div", { class: "warn" }, `Could not load: ${p}`)),
    ...(snap.sources.length ? snap.sources.map(card) : [el("div", { class: "none" }, "Nothing yet. Add the first one above.")]),
    el("div", { class: "toolbar import" }, el("span", { class: "dim" }, "Import a file a teammate exported:"), importInput, mode,
      el("button", { class: "btn small", onclick: importFile }, "Import")),
    state.importResult && el("div", { id: "import-result" },
      el("div", { class: "ok" }, `Imported ${state.importResult.imported}.`),
      ...state.importResult.skipped.map((s) => el("div", { class: "warn" }, `Skipped ${s.label}: ${s.reason}`))));
}

async function importFile() {
  const file = $("#import-file").files[0];
  state.notice = null;
  if (!file) { state.importResult = null; state.notice = { kind: "error", text: "Choose a file first." }; renderForm(); return; }
  try {
    const parsed = JSON.parse(await file.text());
    const list = Array.isArray(parsed) ? parsed : parsed.sources;
    const name = state.draft.author || rememberedName();
    state.importResult = await api("/api/custom-sources/import", {
      method: "POST", body: { sources: list, mode: $("#import-mode").value, author: name, expected_revision: state.snap.revision },
    });
    await load();
  } catch (err) {
    state.importResult = null;
    state.notice = { kind: "error", text: err instanceof SyntaxError ? "That file is not valid JSON." : err.message, reload: err.status === 409 };
    renderForm();
  }
}

// boot ----------------------------------------------------------------

function renderIntro() {
  $("#intro").replaceChildren(
    el("h2", {}, "Sources"),
    el("p", {}, "A source is a few searches plus a rule for what to keep. Add one here and it shows up in the dashboard's search sources straight away, no restart and no code."),
    el("p", { class: "dim" }, "Sources made here only read what a search engine already shows. Nothing on this page touches a client. If you need a source that calls an API or a client's own site, that is a plugin file, see the README."));
}

async function load(done) {
  state.snap = await api("/api/custom-sources");
  state.notice = done && done.ok ? { kind: "ok", text: done.ok } : null;
  renderForm();
  renderList();
}

async function boot() {
  const [meta, engagements] = await Promise.all([api("/api/meta"), api("/api/engagements")]);
  state.categories = meta.categories;
  state.engagements = engagements;
  state.draft = blank();
  renderIntro();
  await load();
}

boot().catch((err) => {
  $("#main").replaceChildren(el("section", { class: "card" }, el("div", { class: "error" }, `Could not start: ${err.message}`)));
});
