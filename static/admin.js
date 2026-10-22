"use strict";

// Admin page. Same rule as the dashboard: everything shown is set with textContent, never as markup.
// The few helpers below are copies of the ones in app.js, so this page does not depend on that file.

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
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
  return data;
}

// "2026-10-21 18:40:12" is UTC. The register shows it as stored, plus the same moment on this machine's clock.
function asDate(utc) {
  if (!utc) return null;
  const d = new Date(utc.replace(" ", "T") + "Z");
  return Number.isNaN(d.getTime()) ? null : d;
}
const utcText = (utc) => (utc ? `${utc} UTC` : "not recorded");
const localText = (utc) => {
  const d = asDate(utc);
  return d ? d.toLocaleString() : "not recorded";
};

const state = {
  section: "roe",
  roe: [],
  slug: "",
  runId: "",
  level: "info",
  lines: "300",
  auto: false,
  timer: null,
  poll: null,
  error: null,
};

const SECTIONS = [["roe", "ROE register"], ["verify", "Verify keys and endpoints"], ["events", "Run events"], ["applog", "App log"]];

function renderSections() {
  $("#sections").replaceChildren(...SECTIONS.map(([key, label]) =>
    el("button", {
      "aria-pressed": String(state.section === key),
      onclick: () => { state.section = key; state.error = null; stopTimer(); stopPoll(); render(); },
    }, label)));
}

function stopTimer() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
}

function stopPoll() {
  if (state.poll) clearTimeout(state.poll);
  state.poll = null;
}

function select(options, value, onchange, label) {
  return el("select", { "aria-label": label, onchange: (ev) => onchange(ev.target.value) },
    ...options.map(([v, text]) => el("option", { value: v, selected: v === value }, text)));
}

// ROE register -------------------------------------------------------

async function loadRoe() {
  state.roe = await api("/api/admin/roe");
}

function roeCard(e) {
  const target = [e.company, e.domain, e.ip].filter(Boolean).join("  |  ") || "no target given";
  const last = e.history[e.history.length - 1];
  return el("div", { class: "roe-card" },
    el("div", { class: "controls" },
      el("h3", {}, e.name),
      el("span", { class: e.authorized ? "badge on" : "badge off" }, e.authorized ? "DEEP DIVE UNLOCKED" : "DEEP DIVE LOCKED")),
    el("div", { class: "dim" }, target),
    el("div", {}, "Current reference: ", el("strong", {}, e.auth_ref || "none"),
      last && ` (${last.action} by ${last.recorded_by}, ${utcText(last.recorded_at)})`),
    e.history.length
      ? el("div", { class: "tablewrap" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["#", "Action", "Reference", "Recorded by", "Date and time (UTC)", "Local time"].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...e.history.map((h, i) => el("tr", {},
            el("td", {}, i + 1), el("td", {}, h.action), el("td", {}, h.auth_ref || "(none)"),
            el("td", {}, h.recorded_by), el("td", {}, utcText(h.recorded_at)), el("td", { class: "dim" }, localText(h.recorded_at)))))))
      : el("div", { class: "none" }, "No authorization has been recorded for this engagement."));
}

function renderRoe(panel) {
  const total = state.roe.reduce((n, e) => n + e.history.length, 0);
  panel.replaceChildren(
    el("p", { class: "dim" }, `${state.roe.length} engagement${state.roe.length === 1 ? "" : "s"}, ${total} ROE record${total === 1 ? "" : "s"}. ` +
      "Records are append only here. They are a log on this machine, not tamper proof, so every change is also in the app log."),
    ...(state.roe.length ? state.roe.map(roeCard) : [el("div", { class: "none" }, "No engagements yet.")]));
}

// verify keys and endpoints -------------------------------------------

const STATUS_TEXT = { ok: "OK", fail: "FAILED", warn: "WARNING", missing: "NOT SET UP", unchecked: "NOT CHECKED" };

async function verifyNow(only) {
  try {
    await api("/api/verify", { method: "POST", body: only ? { only } : {} });
  } catch (err) {
    state.error = err.message;
  }
  render();
}

async function renderVerify(panel) {
  const v = await api("/api/verify");
  const running = v.state === "running";
  const counts = {};
  for (const r of v.results) counts[r.status] = (counts[r.status] || 0) + 1;
  const summary = Object.keys(STATUS_TEXT).filter((s) => counts[s]).map((s) => `${counts[s]} ${STATUS_TEXT[s].toLowerCase()}`).join(", ");

  panel.replaceChildren(
    el("p", { class: "dim" },
      "Checks that each source's address answers and that its key is accepted, before you trust a scan to it. It asks the services about example.com, never your client, and keys only travel in request headers. " +
      "DuckDuckGo is never queried live (a test query is what trips its throttle), and a Brave check uses one search from your quota."),
    el("div", { class: "toolbar" },
      el("button", { class: "btn primary", disabled: running, onclick: () => verifyNow(null) }, running ? `Checking ${v.current || ""} (${v.done}/${v.total})` : "Verify everything"),
      el("span", { class: "dim" }, v.checked_at ? `Last run ${v.checked_at} UTC. ${summary}.` : "Never run on this machine yet.")),
    v.error && el("div", { class: "error" }, v.error),
    state.error && el("div", { class: "error" }, state.error),
    v.results.length
      ? el("div", { class: "tablewrap" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["Status", "What", "Tier", "Result", "Checked (UTC)", ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...v.results.map((r) => el("tr", {},
            el("td", { class: `vs-${r.status}` }, STATUS_TEXT[r.status] || r.status),
            el("td", {}, r.label),
            el("td", { class: "dim" }, r.tier),
            el("td", { class: "notes" }, r.detail, r.cost && el("div", { class: "dim" }, r.cost)),
            el("td", { class: "dim" }, `${r.checked_at} (${r.took_ms} ms)`),
            el("td", {}, el("button", { class: "btn small", disabled: running, onclick: () => verifyNow([r.id]) }, "Re-check")))))))
      : el("div", { class: "none" }, "No results yet. Press Verify everything."));
  state.error = null;
  if (running) state.poll = setTimeout(render, 1000);
}

// run events ---------------------------------------------------------

const LEVEL_OPTIONS = [["debug", "debug and up"], ["info", "info and up"], ["warning", "warnings and errors"], ["error", "errors only"]];

async function renderEvents(panel) {
  if (!state.roe.length) {
    panel.replaceChildren(el("div", { class: "none" }, "No engagements yet."));
    return;
  }
  if (!state.roe.some((e) => e.slug === state.slug)) state.slug = state.roe[0].slug;
  const [runs, events] = await Promise.all([
    api(`/api/engagements/${encodeURIComponent(state.slug)}/runs`),
    api(`/api/engagements/${encodeURIComponent(state.slug)}/events?level=${state.level}&limit=${state.lines}` +
      (state.runId ? `&run_id=${encodeURIComponent(state.runId)}` : "")),
  ]);
  const runOptions = [["", "all runs"], ...runs.runs.map((r) => [String(r.id), `#${r.id} ${r.plugin} (${r.status}, ${r.started_at})`])];
  const toolbar = el("div", { class: "toolbar" },
    select(state.roe.map((e) => [e.slug, e.name]), state.slug, (v) => { state.slug = v; state.runId = ""; render(); }, "Engagement"),
    select(runOptions, state.runId, (v) => { state.runId = v; render(); }, "Run"),
    select(LEVEL_OPTIONS, state.level, (v) => { state.level = v; render(); }, "Level"),
    select([["100", "last 100"], ["300", "last 300"], ["1000", "last 1000"]], state.lines, (v) => { state.lines = v; render(); }, "How many"),
    autoBox(), el("button", { class: "btn small", onclick: render }, "Refresh"));
  const box = el("div", { class: "logbox", id: "logbox", tabindex: "0" });
  if (!events.length) box.append(el("span", { class: "dim" }, "Nothing at this level yet."));
  for (const ev of events) {
    box.append(el("div", { class: `lv-${ev.level}` }, `${ev.at} UTC  ${ev.level.toUpperCase().padEnd(7)} [run ${ev.run_id ?? "-"}] ${ev.message}`));
  }
  panel.replaceChildren(toolbar, box);
  box.scrollTop = box.scrollHeight;
}

// app log ------------------------------------------------------------

async function renderAppLog(panel) {
  const data = await api(`/api/admin/logs?lines=${state.lines}` + (state.level === "debug" ? "" : `&level=${state.level}`));
  const toolbar = el("div", { class: "toolbar" },
    select(LEVEL_OPTIONS, state.level, (v) => { state.level = v; render(); }, "Level"),
    select([["100", "last 100"], ["300", "last 300"], ["1000", "last 1000"]], state.lines, (v) => { state.lines = v; render(); }, "How many"),
    autoBox(), el("button", { class: "btn small", onclick: render }, "Refresh"),
    el("span", { class: "dim" }, `${data.path} (log level ${data.level})`));
  const box = el("div", { class: "logbox", id: "logbox", tabindex: "0" });
  if (!data.lines.length) box.append(el("span", { class: "dim" }, "Nothing logged yet."));
  for (const line of data.lines) {
    const m = / (WARNING|ERROR|DEBUG) /.exec(line);
    box.append(el("div", { class: m ? `lv-${m[1].toLowerCase()}` : "" }, line));
  }
  panel.replaceChildren(toolbar, box);
  box.scrollTop = box.scrollHeight;
}

function autoBox() {
  return el("label", { class: "dim" },
    el("input", {
      type: "checkbox", checked: state.auto,
      onchange: (ev) => { state.auto = ev.target.checked; startTimer(); },
    }), " auto refresh");
}

function startTimer() {
  stopTimer();
  if (state.auto && state.section !== "roe") state.timer = setInterval(render, 3000);
}

// boot ---------------------------------------------------------------

async function render() {
  renderSections();
  const panel = $("#panel");
  try {
    await loadRoe();
    if (state.section === "roe") renderRoe(panel);
    else if (state.section === "verify") await renderVerify(panel);
    else if (state.section === "events") await renderEvents(panel);
    else await renderAppLog(panel);
    state.error = null;
  } catch (err) {
    stopTimer();
    panel.replaceChildren(el("div", { class: "error" }, `Could not load: ${err.message}`));
  }
}

render();
