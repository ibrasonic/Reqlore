"use strict";

async function init() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const state = document.getElementById("state");
  const form = document.getElementById("tabForm");
  if (!tab || tab.id == null) {
    state.className = "status status-err";
    state.textContent = "No active tab.";
    form.querySelector("button[type=submit]").disabled = true;
    return;
  }

  const off = await browser.runtime.sendMessage({
    type: "dom_hunter.tabOff.get", tabId: tab.id,
  });
  const onRadio  = form.querySelector('input[value="on"]');
  const offRadio = form.querySelector('input[value="off"]');
  if (off && off.off) offRadio.checked = true; else onRadio.checked = true;

  const settings = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" });
  let cfg = null;
  let diag = null;
  try { cfg = await browser.runtime.sendMessage({ type: "dom_hunter.getProjectConfig" }); }
  catch (_) {}
  if (!cfg) {
    try { diag = await browser.runtime.sendMessage({ type: "dom_hunter.diagnose" }); }
    catch (_) {}
  }

  if (cfg) {
    state.className = "status status-ok";
    state.textContent = "Configured. Reporting to " + (settings.baseUrl || "Reqlore") + ".";
  } else if (diag && diag.kind === "http" && diag.status === 401) {
    state.className = "status status-err";
    state.textContent = "Token mismatch (HTTP 401). Keep `reqlore both`/`ui` and `reqlore browser` on the same --project, then reload tab.";
  } else if (!settings.token || !settings.baseUrl) {
    state.className = "status status-warn";
    state.textContent = "Not configured yet. Open the options page to set the "
                       + "Reqlore base URL and bridge token.";
  } else {
    state.className = "status status-warn";
    state.textContent = "Configured, but cannot reach Reqlore right now.";
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const chosen = form.querySelector('input[name="state"]:checked');
    if (!chosen) return;
    await browser.runtime.sendMessage({
      type: "dom_hunter.tabOff.set", tabId: tab.id, off: chosen.value === "off",
    });
    try { await browser.tabs.reload(tab.id); } catch (_) {}
    window.close();
  });

  document.getElementById("openSidebar").addEventListener("click", async () => {
    try { await browser.sidebarAction.open(); window.close(); }
    catch (_) { /* sidebar.open requires user gesture; the click counts */ }
  });
  document.getElementById("openFindings").addEventListener("click", async () => {
    // Project-level config, not the per-tab one -- the popup pages run
    // as an extension page so a per-tab `requestConfig` here would be
    // scope-gated against the moz-extension:// URL and lose `ui_url`.
    const cfg = await browser.runtime.sendMessage({ type: "dom_hunter.getProjectConfig" });
    const base = (settings.baseUrl || "").replace(/\/+$/, "");
    const url = (cfg && cfg.ui_url) || (base + "/dom-hunter/");
    await browser.tabs.create({ url });
    window.close();
  });
  document.getElementById("openOptions").addEventListener("click", () => {
    browser.runtime.openOptionsPage();
    window.close();
  });
}

init().catch(err => {
  const state = document.getElementById("state");
  state.className = "status status-err";
  state.textContent = "Error: " + (err && err.message || err);
});
