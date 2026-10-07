"use strict";

// Everything scraped from the web is rendered with textContent only. Never innerHTML.

const state = {
  meta: null,
  engagements: [],
  active: null,
  tier: "search",
  category: "employees",
  filter: "",
  findings: [],
  runs: [],
  runStatus: { state: "idle" },
  notice: null,
  poll: null,
};

const $ = (sel, root = document) => root.querySelector(sel);

// replaceChildren stringifies null and false into visible text, so drop them first.
function replaceKids(host, ...kids) {
  host.replaceChildren(...kids.filter((k) => k != null && k !== false));
}

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

function safeUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: opts.body ? { "Content-Type": "application/json" } : {},
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
  return data;
}

const active = () => state.engagements.find((e) => e.slug === state.active);
const totalOf = (e) => Object.values(e.counts || {}).reduce((a, b) => a + b, 0);

// tabs ---------------------------------------------------------------

function renderTabs() {
  const nav = $("#tabs");
  nav.replaceChildren(
    ...state.engagements.map((e) =>
      el("button", {
        class: "tab", role: "tab", "aria-selected": String(e.slug === state.active),
        onclick: () => selectEngagement(e.slug),
      }, e.name, el("span", { class: "n" }, totalOf(e)))
    ),
    el("button", { class: "tab new", onclick: openNewDialog }, "+ NEW")
  );
}

// main ---------------------------------------------------------------

function renderMain() {
  const main = $("#main");
  const e = active();
  if (!e) {
    main.replaceChildren(
      el("section", { class: "card empty" },
        el("h2", {}, "No engagements yet"),
        el("p", {}, "Start one per client. Each gets its own tab and its own database, so nothing crosses over."),
        el("button", { class: "btn primary", onclick: openNewDialog }, "New engagement"))
    );
    return;
  }
  main.replaceChildren(
    el("section", { class: "card", id: "head" }),
    el("section", { class: "card", id: "controls" }),
    el("section", { class: "card", id: "plugins" }),
    el("section", { class: "card", id: "findings" }),
    el("section", { class: "card", id: "runs" })
  );
  renderHead();
  renderControls();
  renderPlugins();
  renderFindings();
  renderRuns();
}

function renderHead() {
  const e = active();
  if (!e) return;
  const host = $("#head");
  const kv = (k, v) => el("div", {}, el("div", { class: "k" }, k), el("div", { class: "v" }, v || "not given"));
  const refInput = el("input", { type: "text", id: "auth-ref", value: e.auth_ref || "", placeholder: "Authorization reference (SOW, ROE, ticket)" });
  const authBox = el("input", { type: "checkbox", id: "auth-box", checked: e.authorized });
  const scopeForm = el("form", {
    onsubmit: async (ev) => {
      ev.preventDefault();
      try {
        await api(`/api/engagements/${e.slug}`, {
          method: "PATCH",
          body: { auth_ref: refInput.value, authorized: authBox.checked },
        });
        state.notice = null;
        await loadEngagements();
        renderTabs();
        renderHead();
        renderControls();
      } catch (err) {
        state.notice = { kind: "error", text: err.message };
        renderControls();
      }
    },
  },
    refInput,
    el("label", { class: "dim" }, authBox, " authorized for active testing"),
    el("button", { class: "btn small", type: "submit" }, "Save scope")
  );

  host.replaceChildren(
    el("div", { class: "controls" },
      el("h2", {}, e.name),
      el("span", { class: e.authorized ? "badge on" : "badge off" }, e.authorized ? "DEEP DIVE UNLOCKED" : "DEEP DIVE LOCKED"),
      el("span", { class: "spacer" }),
      el("button", {
        class: "btn small danger",
        onclick: async () => {
          if (!confirm(`Delete "${e.name}" and all its findings? This cannot be undone.`)) return;
          try {
            await api(`/api/engagements/${e.slug}`, { method: "DELETE" });
            state.active = null;
            await loadEngagements();
            if (state.engagements.length) await selectEngagement(state.engagements[0].slug);
            else { renderTabs(); renderMain(); }
          } catch (err) {
            state.notice = { kind: "error", text: err.message };
            renderControls();
          }
        },
      }, "Delete engagement")),
    el("div", { class: "target" }, kv("Company", e.company), kv("Domain", e.domain), kv("IP or range", e.ip)),
    el("div", { class: "scope", style: "margin-top:14px" },
      el("h3", {}, "Scope"),
      scopeForm,
      !e.authorized && el("div", { class: "dim" }, "Search tier works without this. Deep dive sends traffic to the client, so it waits for a reference you can point to later."))
  );
}

function renderControls() {
  const e = active();
  const host = $("#controls");
  if (!e) return;
  const running = state.runStatus.state === "running";
  const locked = state.tier === "deep" && !e.authorized;
  const exportLink = (fmt, label) =>
    el("a", { class: "btn", href: `/api/engagements/${e.slug}/export?format=${fmt}`, download: true }, label);

  let statusText = "Idle.";
  let statusClass = "status";
  if (running) {
    const s = state.runStatus;
    statusText = `Running ${s.tier} tier: ${s.current || "starting"} (${s.done}/${s.total})`;
    statusClass = "status running";
  } else if (state.runStatus.error) {
    statusText = state.runStatus.error;
  } else if (state.runStatus.summary) {
    const s = state.runStatus.summary;
    statusText = `Last run: ${s.new_findings} new finding${s.new_findings === 1 ? "" : "s"}` +
      (s.searches_live != null ? `, ${s.searches_live} live search${s.searches_live === 1 ? "" : "es"}, ${s.searches_cached} from cache` : "") + ".";
  }

  replaceKids(host,
    el("div", { class: "controls" },
      el("div", { class: "seg", role: "group", "aria-label": "Mode" },
        el("button", { "aria-pressed": String(state.tier === "search"), onclick: () => setTier("search") }, "SEARCH"),
        el("button", { "aria-pressed": String(state.tier === "deep"), onclick: () => setTier("deep") }, "DEEP DIVE")),
      el("button", {
        class: "btn primary", disabled: running || locked,
        onclick: () => startRun(null),
      }, state.tier === "deep" ? "Run all deep dive sources" : "Run all search sources"),
      el("span", { class: "spacer" }),
      exportLink("md", "Export MD"), exportLink("pdf", "Export PDF"), exportLink("json", "Export JSON")),
    el("div", { class: statusClass, role: "status" }, statusText),
    state.notice && el("div", { class: state.notice.kind === "error" ? "error" : "warn" }, state.notice.text),
    locked && el("div", { class: "warn" }, "Deep dive is locked. Add an authorization reference under Scope above.")
  );
}

function lastRunFor(name) {
  return state.runs.find((r) => r.plugin === name);
}

function renderPlugins() {
  const e = active();
  const host = $("#plugins");
  if (!e) return;
  const running = state.runStatus.state === "running";
  const locked = state.tier === "deep" && !e.authorized;
  const list = state.meta.plugins.filter((p) => p.tier === state.tier);
  replaceKids(host,
    el("h3", {}, state.tier === "deep" ? "Deep dive sources" : "Search sources"),
    el("div", { class: "plugins" }, ...list.map((p) => {
      const last = lastRunFor(p.name);
      const lastText = last
        ? `${last.status}, ${last.found} new, ${last.started_at} UTC${last.error ? " | " + last.error : ""}`
        : "never run";
      return el("div", { class: "plugin" },
        el("div", { class: "name" }, p.name,
          p.touches_target && el("span", { class: "badge active", title: "Sends traffic to the client" }, "ACTIVE")),
        el("button", { class: "btn small", disabled: running || locked, onclick: () => startRun([p.name]) }, "Run"),
        el("div", { class: "desc" }, p.description),
        el("div", { class: "last" }, "Last: ", el("span", { class: last ? `st-${last.status}` : "" }, lastText)));
    })),
    Object.keys(state.meta.plugin_load_errors || {}).length > 0 &&
      el("div", { class: "error" }, "Plugin load errors: " +
        Object.entries(state.meta.plugin_load_errors).map(([f, m]) => `${f}: ${m}`).join("; "))
  );
}

function renderFindings() {
  const e = active();
  const host = $("#findings");
  if (!e) return;
  const counts = {};
  for (const f of state.findings) counts[f.category] = (counts[f.category] || 0) + 1;

  const rows = state.findings.filter((f) => {
    if (f.category !== state.category) return false;
    if (!state.filter) return true;
    const hay = `${f.value} ${f.notes || ""} ${f.plugins.join(" ")}`.toLowerCase();
    return hay.includes(state.filter.toLowerCase());
  });

  const cats = el("div", { class: "cats", role: "group", "aria-label": "Category" },
    ...state.meta.categories.map((c) =>
      el("button", {
        "aria-pressed": String(c.key === state.category),
        onclick: () => { state.category = c.key; renderFindings(); },
      }, c.label, el("span", { class: "n" }, counts[c.key] || 0))));

  const filter = el("input", {
    type: "search", class: "filter", placeholder: "Filter this list", value: state.filter, "aria-label": "Filter findings",
    oninput: (ev) => {
      state.filter = ev.target.value;
      renderFindings();
      const again = $("#findings .filter");
      again.focus();
      again.setSelectionRange(state.filter.length, state.filter.length);
    },
  });

  let body;
  if (!rows.length) {
    body = el("div", { class: "none" }, state.findings.length || state.filter
      ? "Nothing here."
      : "Nothing yet. Run the search sources to start collecting.");
  } else {
    body = el("div", { class: "tablewrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ...["Finding", "Conf.", "Source", "Notes", ""].map((h) => el("th", {}, h)))),
      el("tbody", {}, ...rows.map(findingRow))));
  }
  host.replaceChildren(el("h3", {}, "Findings"), cats, filter, body);
}

function findingRow(f) {
  const href = f.url && safeUrl(f.url);
  const valueNode = href && f.category === "documents"
    ? el("a", { href, target: "_blank", rel: "noopener noreferrer" }, f.value)
    : f.value;
  const evidence = href && f.category !== "documents"
    ? el("div", {}, el("a", { href, target: "_blank", rel: "noopener noreferrer", class: "src" }, "evidence"))
    : null;
  return el("tr", { class: f.verified ? "verified" : "" },
    el("td", { class: "val" }, valueNode, evidence),
    el("td", { class: "num" }, el("span", { class: "conf" }, f.confidence)),
    el("td", { class: "src" }, f.plugins.join(", ")),
    el("td", { class: "notes" }, f.notes || ""),
    el("td", {},
      el("label", { class: "dim", title: "Mark as verified by you" },
        el("input", {
          type: "checkbox", checked: f.verified,
          onchange: async (ev) => {
            await api(`/api/engagements/${state.active}/findings/${f.id}`, { method: "PATCH", body: { verified: ev.target.checked } });
            f.verified = ev.target.checked;
            renderFindings();
          },
        }), " ok "),
      el("button", {
        class: "btn small danger", title: "Remove this finding",
        onclick: async () => {
          await api(`/api/engagements/${state.active}/findings/${f.id}`, { method: "DELETE" });
          state.findings = state.findings.filter((x) => x.id !== f.id);
          renderFindings();
          loadEngagements().then(renderTabs);
        },
      }, "Drop")));
}

function renderRuns() {
  const host = $("#runs");
  if (!host) return;
  const rows = state.runs.slice(0, 60);
  host.replaceChildren(el("details", {},
    el("summary", {}, `Run history (${state.runs.length})`),
    rows.length
      ? el("div", { class: "runlog tablewrap" }, el("table", {},
          el("thead", {}, el("tr", {}, ...["Source", "Tier", "Started (UTC)", "Status", "New", "Error"].map((h) => el("th", {}, h)))),
          el("tbody", {}, ...rows.map((r) => el("tr", {},
            el("td", {}, r.plugin), el("td", {}, r.tier), el("td", {}, r.started_at),
            el("td", { class: `st-${r.status}` }, r.status), el("td", {}, r.found), el("td", { class: "notes" }, r.error || ""))))))
      : el("div", { class: "none" }, "No runs yet.")));
}

// actions ------------------------------------------------------------

function setTier(tier) {
  state.tier = tier;
  state.notice = null;
  renderControls();
  renderPlugins();
}

async function startRun(names) {
  state.notice = null;
  try {
    state.runStatus = await api(`/api/engagements/${state.active}/runs`, {
      method: "POST", body: { tier: state.tier, plugins: names },
    });
    startPolling();
  } catch (err) {
    state.notice = { kind: "error", text: err.message };
  }
  renderControls();
  renderPlugins();
}

function startPolling() {
  stopPolling();
  state.poll = setInterval(refreshActive, 1500);
  refreshActive();
}

function stopPolling() {
  if (state.poll) clearInterval(state.poll);
  state.poll = null;
}

async function refreshActive() {
  if (!state.active) return stopPolling();
  const slug = state.active;
  try {
    const [runs, findings] = await Promise.all([
      api(`/api/engagements/${slug}/runs`),
      api(`/api/engagements/${slug}/findings`),
    ]);
    if (slug !== state.active) return;
    state.runStatus = runs.status;
    state.runs = runs.runs;
    state.findings = findings;
    renderControls();
    renderPlugins();
    renderFindings();
    renderRuns();
    if (runs.status.state !== "running") {
      stopPolling();
      await loadEngagements();
      renderTabs();
    }
  } catch (err) {
    state.notice = { kind: "error", text: err.message };
    stopPolling();
    renderControls();
  }
}

async function loadEngagements() {
  state.engagements = await api("/api/engagements");
}

async function selectEngagement(slug) {
  stopPolling();
  state.active = slug;
  state.filter = "";
  state.notice = null;
  state.findings = [];
  state.runs = [];
  state.runStatus = { state: "idle" };
  renderTabs();
  renderMain();
  await refreshActive();
  if (state.runStatus.state === "running") startPolling();
}

// new engagement dialog ----------------------------------------------

function openNewDialog() {
  $("#new-form").reset();
  $("#new-error").textContent = "";
  $("#new-dlg").showModal();
  $("#new-form [name=name]").focus();
}

function wireDialog() {
  $("#new-cancel").addEventListener("click", () => $("#new-dlg").close());
  $("#new-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    try {
      const created = await api("/api/engagements", {
        method: "POST",
        body: {
          name: f.get("name"), company: f.get("company"), domain: f.get("domain"),
          ip: f.get("ip"), auth_ref: f.get("auth_ref"), authorized: f.get("authorized") === "on",
        },
      });
      $("#new-dlg").close();
      await loadEngagements();
      await selectEngagement(created.slug);
    } catch (err) {
      $("#new-error").textContent = err.message;
    }
  });
}

// boot ---------------------------------------------------------------

function wireTheme() {
  const logo = $(".logo");
  const apply = (name) => {
    if (name === "rose") document.documentElement.dataset.theme = "rose";
    else delete document.documentElement.dataset.theme;
  };
  try { apply(localStorage.getItem("sc-theme")); } catch { /* storage blocked, default theme */ }
  const flip = () => {
    const next = document.documentElement.dataset.theme === "rose" ? "green" : "rose";
    apply(next);
    try { localStorage.setItem("sc-theme", next); } catch { /* not remembered, still works */ }
  };
  logo.setAttribute("role", "button");
  logo.tabIndex = 0;
  logo.title = "Switch theme";
  logo.addEventListener("click", flip);
  logo.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); flip(); } });
}

async function boot() {
  wireTheme();
  wireDialog();
  state.meta = await api("/api/meta");
  await loadEngagements();
  renderTabs();
  if (state.engagements.length) await selectEngagement(state.engagements[0].slug);
  else renderMain();
}

boot().catch((err) => {
  $("#main").replaceChildren(el("section", { class: "card" }, el("div", { class: "error" }, `Could not start: ${err.message}`)));
});
