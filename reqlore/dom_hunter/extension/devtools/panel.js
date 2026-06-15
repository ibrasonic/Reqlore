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

/* Turn a `dom_hunter.diagnose` payload into a one-line, user-facing
 * explanation. The previous panel just said "cannot reach Reqlore at X",
 * which is misleading when Reqlore IS up but the token doesn't match
 * (mismatched --project between `reqlore web` and `reqlore browser`, or
 * a token rotation since the browser was launched). */
function describeBridgeFailure(baseUrl, diag) {
  const where = baseUrl || "(no base URL set)";
  if (!diag) return "cannot reach Reqlore at " + where;
  if (diag.kind === "no-base-url") {
    return "no base URL configured -- open the extension options";
  }
  if (diag.kind === "no-token") {
    return "no bridge token configured -- relaunch via `reqlore browser --project ...` "
         + "or paste the token from Reqlore -> DOM Hunter -> Settings into the extension options";
  }
  if (diag.kind === "http" && diag.status === 401) {
    return "token mismatch at " + where + " (HTTP 401) -- the extension's bridge token does "
         + "not match the project currently served. Make sure `reqlore web` and "
         + "`reqlore browser` use the SAME --project, then relaunch the browser. If you "
         + "rotated the token in Reqlore -> DOM Hunter -> Settings, you must relaunch too.";
  }
  if (diag.kind === "http" && diag.status === 404) {
    return "endpoint missing at " + where + " (HTTP 404) -- is this the Reqlore UI port? "
         + "It should be the UI port (default 8787), not the proxy port (8080).";
  }
  if (diag.kind === "http") {
    return "Reqlore returned HTTP " + diag.status + " at " + where;
  }
  if (diag.kind === "network") {
    return "cannot reach Reqlore at " + where + " (network: "
         + (diag.message || "fetch failed") + ") -- is `reqlore web` running on this port?";
  }
  return "cannot reach Reqlore at " + where;
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
    // Bridge call returned null. Ask the background for a fresh
    // uncached probe so we can show the actual reason (HTTP status,
    // network error, ...) instead of a generic "cannot reach".
    let diag = null;
    try { diag = await browser.runtime.sendMessage({ type: "dom_hunter.diagnose" }); }
    catch (_) {}
    tracerEl.textContent = describeBridgeFailure(settings.baseUrl, diag);
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
    // DevTools pages don't get `browser.tabs` in Firefox even with the
    // `tabs` permission; use the inspected-window API instead, which
    // reloads exactly the tab this panel is attached to.
    if (browser.devtools && browser.devtools.inspectedWindow
        && typeof browser.devtools.inspectedWindow.reload === "function") {
      browser.devtools.inspectedWindow.reload({ ignoreCache: false });
    } else {
      // Last-resort fallback: ask the background (which DOES have
      // tabs) to reload for us.
      await browser.runtime.sendMessage({
        type: "dom_hunter.reloadTab", tabId: INSPECTED_TAB_ID,
      });
    }
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
