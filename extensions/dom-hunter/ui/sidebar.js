"use strict";

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
}

async function refresh() {
  const state = document.getElementById("state");
  const totals = document.getElementById("totals");
  const table = document.getElementById("findingsTable");
  const tbody = document.getElementById("findingsBody");
  const empty = document.getElementById("empty");

  const settings = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" });
  if (!settings || !settings.token || !settings.baseUrl) {
    state.className = "status status-warn";
    state.textContent = "Not configured. Open the extension options to set the "
                      + "Reqlore base URL and bridge token.";
    return;
  }

  const data = await browser.runtime.sendMessage({
    type: "dom_hunter.findings.list", limit: 25,
  });
  if (!data) {
    state.className = "status status-err";
    state.textContent = "Could not reach Reqlore at " + settings.baseUrl + ".";
    return;
  }
  state.className = "status status-ok";
  state.textContent = "Connected to " + settings.baseUrl + ".";
  totals.textContent = "Total: " + (data.total || 0) + " findings reported.";

  tbody.innerHTML = "";
  const rows = data.findings || [];
  if (!rows.length) {
    table.hidden = true;
    empty.hidden = false;
    return;
  }
  empty.hidden = true;
  table.hidden = false;
  const base = (settings.baseUrl || "").replace(/\/+$/, "");
  for (const f of rows) {
    const tr = document.createElement("tr");
    const url = base + "/dom-hunter/finding/" + encodeURIComponent(f.id);
    tr.innerHTML =
      "<td><code>" + escapeHtml(f.sink) + "</code></td>" +
      "<td><code>" + escapeHtml(f.source) + "</code></td>" +
      "<td>" + escapeHtml(f.severity) + "</td>" +
      "<td>" + escapeHtml(f.hit_count) + "</td>" +
      "<td><a href=\"" + escapeHtml(url) + "\" target=\"_blank\" rel=\"noopener\""
        + " aria-label=\"View finding " + escapeHtml(f.id) + ": "
        + escapeHtml(f.source) + " into " + escapeHtml(f.sink) + " on "
        + escapeHtml(f.page_url) + "\">View " + escapeHtml(f.id) + "</a></td>";
    tbody.appendChild(tr);
  }
}

document.getElementById("refreshBtn").addEventListener("click", refresh);
document.getElementById("openReqlore").addEventListener("click", async () => {
  const settings = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" });
  const base = (settings.baseUrl || "http://127.0.0.1:8080").replace(/\/+$/, "");
  await browser.tabs.create({ url: base + "/dom-hunter/" });
});

refresh().catch(err => {
  const state = document.getElementById("state");
  state.className = "status status-err";
  state.textContent = "Error: " + (err && err.message || err);
});
