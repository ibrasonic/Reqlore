/* DOM Hunter DevTools panel.
 *
 * Shows findings and postMessages for the inspected tab. Receives live
 * updates from the background script and falls back to a manual refresh
 * (polling the Reqlore bridge JSON endpoint).
 */
"use strict";

const INSPECTED_TAB_ID = browser.devtools.inspectedWindow.tabId;
const HIDDEN_IDS = new Set();
const HIDDEN_MSG_IDS = new Set();
let inspectedUrl = "";
let inspectedHost = "";

const $ = (id) => document.getElementById(id);
const live = (msg) => { $("live").textContent = msg; };

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function sameHost(url) {
  if (!url || !inspectedHost) return false;
  try { return new URL(url).host.toLowerCase() === inspectedHost; }
  catch (_) { return false; }
}

// -------------------- inspected URL --------------------

async function refreshInspectedUrl() {
  try {
    const [val, err] = await browser.devtools.inspectedWindow.eval(
      "location.href"
    );
    if (err) { inspectedUrl = ""; inspectedHost = ""; return; }
    inspectedUrl = String(val || "");
    try { inspectedHost = new URL(inspectedUrl).host.toLowerCase(); }
    catch (_) { inspectedHost = ""; }
    $("page-url").textContent = inspectedUrl || "(no page)";
  } catch (_) {
    inspectedUrl = ""; inspectedHost = "";
  }
}

// -------------------- status --------------------

async function refreshStatus() {
  let settings = { baseUrl: "", token: "" };
  let projectCfg = null;     // raw bridge config (no per-tab scope filter)
  let tabCfg = null;         // configForTab(inspected) -- tells us in-scope
  try {
    settings = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" });
  } catch (_) {}
  try {
    projectCfg = await browser.runtime.sendMessage({ type: "dom_hunter.getProjectConfig" });
  } catch (_) {}
  try {
    tabCfg = await browser.runtime.sendMessage({
      type: "dom_hunter.requestConfig",
      tabId: INSPECTED_TAB_ID,
      url: inspectedUrl,
    });
  } catch (_) {}

  const tracerEl = $("status-tracer");
  if (!settings || !settings.baseUrl || !settings.token) {
    tracerEl.textContent = "not configured -- open extension options first";
    tracerEl.className = "status status-warn";
  } else if (!projectCfg) {
    tracerEl.textContent = "cannot reach Reqlore at " + settings.baseUrl;
    tracerEl.className = "status status-err";
  } else if (!projectCfg.enabled) {
    tracerEl.textContent = "off (turn on in Reqlore: DOM Hunter -> Settings)";
    tracerEl.className = "status status-warn";
  } else if (tabCfg && tabCfg.enabled) {
    tracerEl.textContent = "on (this tab is in scope)";
    tracerEl.className = "status status-ok";
  } else {
    // Project tracer is on, but this tab is gated out -- either by the
    // scope list or by the per-tab toggle below. Spell out which.
    const offMap = await browser.runtime.sendMessage({
      type: "dom_hunter.tabOff.get", tabId: INSPECTED_TAB_ID,
    }).catch(() => ({ off: false }));
    if (offMap && offMap.off) {
      tracerEl.textContent = "on (project) -- disabled on this tab";
    } else {
      const scope = (projectCfg.scope || []).join(", ") || "(none)";
      tracerEl.textContent = "on (project) -- this tab is OUT OF SCOPE"
                            + (inspectedHost ? " for host '" + inspectedHost + "'" : "")
                            + "; scope = " + scope;
    }
    tracerEl.className = "status status-warn";
  }
  // Canary comes from the PROJECT config so the user can copy/paste it
  // even before they navigate to an in-scope tab.
  $("status-canary").textContent = (projectCfg && projectCfg.canary) || "(none yet)";

  const link = $("status-reqlore-link");
  const uiUrl = (projectCfg && projectCfg.ui_url)
    || (settings && settings.baseUrl
        ? settings.baseUrl.replace(/\/+$/, "") + "/dom-hunter/"
        : "");
  link.href = uiUrl || "#";
  link.textContent = uiUrl || "(set base URL in options)";

  // Per-tab toggle state.
  try {
    const r = await browser.runtime.sendMessage({
      type: "dom_hunter.tabOff.get", tabId: INSPECTED_TAB_ID,
    });
    const on = !(r && r.off);
    document.querySelector('input[name="tab-onoff"][value="' + (on ? "on" : "off") + '"]').checked = true;
  } catch (_) {}
}

// -------------------- findings table --------------------

const findingsState = { rows: [] };
const messagesState = { rows: [] };

function renderFindings() {
  const tbody = $("findings-rows");
  const visible = findingsState.rows.filter(
    r => sameHost(r.page_url) && !HIDDEN_IDS.has(r.id)
  );
  $("findings-count").textContent = "(" + visible.length + ")";
  if (!visible.length) {
    tbody.innerHTML = "";
    $("findings-empty").hidden = false;
    $("findings-table").hidden = true;
    return;
  }
  $("findings-empty").hidden = true;
  $("findings-table").hidden = false;
  const baseUrl = (window.__reqlore_base_url__ || "").replace(/\/+$/, "");
  tbody.innerHTML = visible.map(r => {
    const open = baseUrl
      ? `<a href="${escapeHtml(baseUrl)}/dom-hunter/finding/${r.id}" target="_blank" rel="noopener noreferrer">Open in Reqlore</a>`
      : "Open in Reqlore (set URL)";
    return `
      <tr>
        <td>${escapeHtml(fmtTime(r.ts))}</td>
        <td><code>${escapeHtml(r.sink)}</code></td>
        <td><code>${escapeHtml(r.source)}</code></td>
        <td>${escapeHtml(r.severity)}</td>
        <td>${r.canary_seen ? "yes" : "no"}</td>
        <td>${r.hit_count || 1}</td>
        <td>${open}</td>
      </tr>
    `;
  }).join("");
}

function renderMessages() {
  const tbody = $("messages-rows");
  const visible = messagesState.rows.filter(
    r => sameHost(r.page_url) && !HIDDEN_MSG_IDS.has(r.id)
  );
  $("messages-count").textContent = "(" + visible.length + ")";
  if (!visible.length) {
    tbody.innerHTML = "";
    $("messages-empty").hidden = false;
    $("messages-table").hidden = true;
    return;
  }
  $("messages-empty").hidden = true;
  $("messages-table").hidden = false;
  tbody.innerHTML = visible.map(r => `
    <tr>
      <td>${escapeHtml(fmtTime(r.ts))}</td>
      <td><code>${escapeHtml(r.origin)}</code></td>
      <td>${r.has_canary ? "yes" : "no"}</td>
      <td><code>${escapeHtml((r.data || "").slice(0, 200))}</code></td>
    </tr>
  `).join("");
}

async function refreshFindings() {
  let settings = null;
  try { settings = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" }); }
  catch (_) {}
  window.__reqlore_base_url__ = settings && settings.baseUrl;

  try {
    const r = await browser.runtime.sendMessage({
      type: "dom_hunter.findings.list", limit: 200,
    });
    if (r && Array.isArray(r.findings)) {
      findingsState.rows = r.findings;
      renderFindings();
    }
  } catch (_) {}
}

// -------------------- live events --------------------

browser.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== "dom_hunter.eventAdded") return;
  if (msg.tabId != null && msg.tabId !== INSPECTED_TAB_ID) return;
  const p = msg.payload || {};

  if (p.kind === "message") {
    const row = {
      id: "live-" + Date.now() + "-" + Math.random(),
      ts: Math.floor(Date.now() / 1000),
      page_url: p.page_url || inspectedUrl,
      origin: p.origin || "",
      data: p.data || "",
      has_canary: !!p.has_canary,
    };
    messagesState.rows.unshift(row);
    if (messagesState.rows.length > 500) messagesState.rows.length = 500;
    renderMessages();
    if (p.has_canary) live("New web message containing the canary.");
    return;
  }

  // For findings, the server-assigned id and ts come back via the next
  // refresh; until then, prepend a provisional row.
  const row = {
    id: "live-" + Date.now() + "-" + Math.random(),
    ts: Math.floor(Date.now() / 1000),
    page_url: p.page_url || inspectedUrl,
    sink: p.sink || "?",
    source: p.source || "?",
    severity: p.severity || "medium",
    canary_seen: !!p.canary_seen,
    hit_count: 1,
  };
  findingsState.rows.unshift(row);
  if (findingsState.rows.length > 500) findingsState.rows.length = 500;
  renderFindings();
  live("New finding: " + row.sink + " from " + row.source + " (" + row.severity + ").");
  // Re-sync with server shortly to get the real id + dedupe hit_count.
  setTimeout(refreshFindings, 800);
});

// -------------------- UI handlers --------------------

$("refresh-btn").addEventListener("click", async () => {
  await refreshInspectedUrl();
  await refreshStatus();
  await refreshFindings();
  live("Refreshed.");
});

$("clear-local-btn").addEventListener("click", () => {
  for (const r of findingsState.rows) HIDDEN_IDS.add(r.id);
  for (const r of messagesState.rows) HIDDEN_MSG_IDS.add(r.id);
  renderFindings();
  renderMessages();
  live("Hidden " + (findingsState.rows.length + messagesState.rows.length)
       + " items from this view.");
});

$("tab-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const sel = document.querySelector('input[name="tab-onoff"]:checked');
  if (!sel) return;
  const off = sel.value === "off";
  try {
    await browser.runtime.sendMessage({
      type: "dom_hunter.tabOff.set", tabId: INSPECTED_TAB_ID, off: off,
    });
    await browser.tabs.reload(INSPECTED_TAB_ID);
    live("Tracer " + (off ? "disabled" : "enabled") + " on this tab; reloading.");
  } catch (e) {
    live("Could not change tab state: " + (e && e.message ? e.message : e));
  }
});

// Re-sync when the inspected tab navigates.
browser.devtools.network.onNavigated.addListener(async () => {
  HIDDEN_IDS.clear();
  HIDDEN_MSG_IDS.clear();
  await refreshInspectedUrl();
  await refreshStatus();
  await refreshFindings();
});

// -------------------- boot --------------------

(async function init() {
  await refreshInspectedUrl();
  await refreshStatus();
  await refreshFindings();
})();
