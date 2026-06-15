"use strict";

const $ = (id) => document.getElementById(id);

async function load() {
  const s = await browser.runtime.sendMessage({ type: "dom_hunter.settings.get" });
  // Default to the Reqlore UI port (8787), NOT the proxy port (8080).
  $("baseUrl").value = s.baseUrl || "http://127.0.0.1:8787";
  $("token").value = s.token || "";
  if (s.managed) {
    $("state").className = "status status-ok";
    $("state").textContent = "Settings are managed by the Reqlore browser "
                            + "policy. To override them, launch this extension "
                            + "from a different browser profile.";
    $("baseUrl").readOnly = true;
    $("token").readOnly = true;
  } else if (!s.token || !s.baseUrl) {
    $("state").className = "status status-warn";
    $("state").textContent = "No settings saved yet. Fill in the form and press "
                            + "Save settings.";
  } else {
    $("state").className = "status status-ok";
    $("state").textContent = "Settings loaded.";
  }

  const cmds = await browser.commands.getAll();
  const ul = $("shortcutList");
  ul.innerHTML = "";
  for (const c of cmds) {
    const li = document.createElement("li");
    const kbd = c.shortcut
      ? c.shortcut.split("+").map(k => "<kbd>" + k + "</kbd>").join("+")
      : "(unbound)";
    li.innerHTML = kbd + " &mdash; " + (c.description || c.name);
    ul.appendChild(li);
  }
}

$("showToken").addEventListener("change", (ev) => {
  $("token").type = ev.target.checked ? "text" : "password";
});

$("optsForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const baseUrl = $("baseUrl").value.trim();
  const token = $("token").value.trim();
  if (!/^https?:\/\//i.test(baseUrl)) {
    $("state").className = "status status-err";
    $("state").textContent = "Base URL must start with http:// or https://.";
    $("baseUrl").focus();
    return;
  }
  if (!token) {
    $("state").className = "status status-err";
    $("state").textContent = "Bridge token is required.";
    $("token").focus();
    return;
  }
  await browser.runtime.sendMessage({
    type: "dom_hunter.settings.set",
    settings: { baseUrl, token },
  });
  $("state").className = "status status-ok";
  $("state").textContent = "Settings saved. Reload any open target tabs to pick "
                          + "up the new configuration.";
});

$("testBtn").addEventListener("click", async () => {
  $("state").className = "status status-warn";
  $("state").textContent = "Testing connection...";
  // Project-level config -- the options page is an extension page, so a
  // per-tab requestConfig would be scope-gated against moz-extension://
  // and falsely report the tracer as off.
  const cfg = await browser.runtime.sendMessage({ type: "dom_hunter.getProjectConfig" });
  if (!cfg) {
    $("state").className = "status status-err";
    $("state").textContent = "Could not reach Reqlore with these settings.";
    return;
  }
  $("state").className = "status status-ok";
  $("state").textContent = "Connected. Tracer is currently "
    + (cfg.enabled ? "ON" : "off") + ". Canary length: "
    + (cfg.canary ? cfg.canary.length : 0) + " chars.";
});

load().catch(err => {
  $("state").className = "status status-err";
  $("state").textContent = "Load error: " + (err && err.message || err);
});
