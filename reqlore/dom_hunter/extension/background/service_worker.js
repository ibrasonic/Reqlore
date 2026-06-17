/* Reqlore DOM Hunter -- background service worker.
 *
 * Responsibilities:
 *   - Persist user settings (Reqlore base URL + bridge token).
 *   - Fetch project config from Reqlore on demand and cache it.
 *   - Receive reports from content scripts and POST them to the bridge.
 *   - Handle command shortcuts (toggle, open findings page).
 */
"use strict";

const STORE_KEYS = {
  baseUrl: "dom_hunter.baseUrl",
  token:   "dom_hunter.token",
  tabOff:  "dom_hunter.tabOff",   // map { tabId: true } -- tabs the user disabled
};

// Reqlore's UI server (where /dom-hunter/__bridge/* lives). NOT the
// proxy port (8080). The managed-policy config from `reqlore browser
// --project` overrides this; the default only kicks in when the user
// loaded the extension manually and hasn't touched the options page.
const DEFAULT_BASE_URL = "http://127.0.0.1:8787";

let cachedCfg = null;
let cachedAt = 0;
// Short TTL so toggles in the Reqlore UI (Enabled, Scope, auto-inject)
// take effect within a few seconds without the user having to reload
// the extension or restart Firefox.
const CFG_TTL_MS = 3_000;

// -------------------- settings storage --------------------

async function getSettings() {
  // Bootstrap order:
  //   1. browser.storage.local  -- the most recently-known-good token,
  //      kept up-to-date by fetchConfig() persisting whatever the
  //      bridge response carries. This wins so a token rotated in the
  //      Reqlore UI propagates within a few seconds (the prior token
  //      is still accepted under the server's rotation grace window;
  //      the response hands back the new one, we save it locally).
  //   2. browser.storage.managed -- enterprise-managed seed values
  //      shipped via Firefox policy `3rdparty.Extensions`. Used for
  //      first-install bootstrap and for the baseUrl, which never
  //      rotates. This is what makes `reqlore browser` "just work"
  //      with zero manual configuration.
  //   3. DEFAULT_BASE_URL fallback.
  let managed = {};
  try { managed = await browser.storage.managed.get(); } catch (_) {}
  const r = await browser.storage.local.get([STORE_KEYS.baseUrl, STORE_KEYS.token]);
  return {
    baseUrl: r[STORE_KEYS.baseUrl]
             || (managed && managed.baseUrl) || DEFAULT_BASE_URL,
    token:   r[STORE_KEYS.token]
             || (managed && managed.token)   || "",
    managed: !!(managed && (managed.baseUrl || managed.token)),
  };
}

async function setSettings(s) {
  const obj = {};
  if (typeof s.baseUrl === "string") obj[STORE_KEYS.baseUrl] = s.baseUrl;
  if (typeof s.token   === "string") obj[STORE_KEYS.token]   = s.token;
  await browser.storage.local.set(obj);
  cachedCfg = null;
}

async function getTabOffMap() {
  const r = await browser.storage.local.get(STORE_KEYS.tabOff);
  return r[STORE_KEYS.tabOff] || {};
}

async function setTabOff(tabId, off) {
  const map = await getTabOffMap();
  if (off) map[tabId] = true; else delete map[tabId];
  await browser.storage.local.set({ [STORE_KEYS.tabOff]: map });
}

async function getManagedSeed() {
  try {
    const managed = await browser.storage.managed.get();
    return {
      baseUrl: (managed && typeof managed.baseUrl === "string") ? managed.baseUrl : "",
      token:   (managed && typeof managed.token === "string") ? managed.token : "",
    };
  } catch (_) {
    return { baseUrl: "", token: "" };
  }
}

async function bridgeRequest(path, init) {
  const { baseUrl, token } = await getSettings();
  if (!baseUrl || !token) return null;

  const url = baseUrl.replace(/\/+$/, "") + path;
  const managed = await getManagedSeed();
  let usedToken = token;
  let r = await fetch(url, {
    method: (init && init.method) || "GET",
    headers: Object.assign({}, (init && init.headers) || {}, {
      "X-DOMHunter-Token": usedToken,
      "Accept": "application/json",
    }),
    body: init && init.body,
    cache: "no-store",
    credentials: "omit",
  });

  // If local token is stale, retry once with managed-policy token.
  if (r.status === 401 && managed.token && managed.token !== usedToken) {
    const rr = await fetch(url, {
      method: (init && init.method) || "GET",
      headers: Object.assign({}, (init && init.headers) || {}, {
        "X-DOMHunter-Token": managed.token,
        "Accept": "application/json",
      }),
      body: init && init.body,
      cache: "no-store",
      credentials: "omit",
    });
    if (rr.ok) {
      r = rr;
      usedToken = managed.token;
      // Persist fallback token so subsequent calls stop hitting 401.
      try {
        await browser.storage.local.set({ [STORE_KEYS.token]: usedToken });
      } catch (_) {}
    }
  }

  return { response: r, baseUrl, token, usedToken };
}

// -------------------- bridge to Reqlore --------------------

async function fetchConfig() {
  const now = Date.now();
  if (cachedCfg && (now - cachedAt) < CFG_TTL_MS) return cachedCfg;
  try {
    const req = await bridgeRequest("/dom-hunter/__bridge/config", { method: "GET" });
    if (!req || !req.response || !req.response.ok) return null;
    const cfg = await req.response.json();
    const finalToken = (cfg && typeof cfg.token === "string" && cfg.token)
      ? cfg.token : req.usedToken;
    // Self-healing token rotation: if Reqlore handed us a token that
    // differs from what we just used to authenticate, persist it so
    // every subsequent request uses the fresh value. The just-used
    // token was the previous one (still accepted under the server's
    // grace window); next call will use the new one.
    if (finalToken && finalToken !== req.token) {
      try {
        await browser.storage.local.set({ [STORE_KEYS.token]: finalToken });
      } catch (_) {}
    }
    cachedCfg = cfg;
    cachedAt = now;
    return cachedCfg;
  } catch (_) {
    return null;
  }
}

/* Uncached one-shot probe used by panel/options for diagnostics. Returns:
 *   {ok:true, baseUrl, token:bool}                              -- bridge reachable, 200
 *   {ok:false, kind:"no-base-url", baseUrl, token:bool}        -- baseUrl missing
 *   {ok:false, kind:"no-token",    baseUrl, token:bool}        -- token missing
 *   {ok:false, kind:"http",   status, baseUrl, token:bool}     -- got non-2xx (e.g. 401)
 *   {ok:false, kind:"network", message, baseUrl, token:bool}   -- fetch threw
 * The panel uses this to tell the user WHY the bridge call failed (token
 * mismatch vs. Reqlore not running vs. unconfigured) instead of just
 * "cannot reach Reqlore".
 */
async function diagnoseBridge() {
  const { baseUrl, token } = await getSettings();
  const hasToken = !!token;
  if (!baseUrl) return { ok: false, kind: "no-base-url", baseUrl: "", token: hasToken };
  if (!hasToken) return { ok: false, kind: "no-token", baseUrl, token: false };
  try {
    const req = await bridgeRequest("/dom-hunter/__bridge/config", { method: "GET" });
    if (!req || !req.response) {
      return { ok: false, kind: "no-token", baseUrl, token: false };
    }
    if (req.response.ok) return { ok: true, baseUrl: req.baseUrl, token: true };
    return {
      ok: false,
      kind: "http",
      status: req.response.status,
      baseUrl: req.baseUrl,
      token: true,
    };
  } catch (e) {
    return {
      ok: false, kind: "network",
      message: (e && e.message) ? String(e.message) : String(e),
      baseUrl, token: true,
    };
  }
}

async function sendReport(payload, tabId) {
  try {
    const req = await bridgeRequest("/dom-hunter/__bridge/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });
    if (req && req.response && req.response.ok) {
      // Broadcast to every interested view (popup, sidebar, devtools panel).
      try {
        browser.runtime.sendMessage({
          type: "dom_hunter.eventAdded",
          tabId: tabId || null,
          payload: payload,
        }).catch(() => {});
      } catch (_) {}
    }
    return !!(req && req.response && req.response.ok);
  } catch (_) { return false; }
}

// -------------------- per-tab gating --------------------

// -------------------- scope helpers --------------------

/* Mirrors reqlore.dom_hunter.normalize_scope_entry on the JS side --
 * defensive only: the server normalizes too, but the bridge config is
 * cached for up to CFG_TTL_MS so legacy / hand-edited entries flow
 * through here unaltered for a short window. */
function normalizeScopeEntry(s) {
  s = String(s == null ? "" : s).trim().toLowerCase();
  if (!s) return "";
  if (s.startsWith("*.")) {
    let rest = s.slice(2);
    const i = rest.indexOf("://");
    if (i >= 0) rest = rest.slice(i + 3);
    rest = rest.split(/[\/?#]/)[0];
    return rest ? ("*." + rest) : "";
  }
  if (s.indexOf("://") >= 0) {
    try { return new URL(s).host.toLowerCase(); } catch (_) { return ""; }
  }
  if (s.startsWith("//")) s = s.slice(2);
  return s.split(/[\/?#]/)[0];
}

async function configForTab(tabId, url) {
  const cfg = await fetchConfig();
  if (!cfg) return null;
  if (!cfg.enabled) return { enabled: false };
  const offMap = await getTabOffMap();
  if (offMap[tabId]) return { enabled: false };

  // Scope check (host string match; same logic as the server).
  let host = "";
  try { host = new URL(url || "").host.toLowerCase(); } catch (_) {}
  const scope = Array.isArray(cfg.scope) ? cfg.scope : [];
  if (scope.length) {
    const inScope = scope.some(p => {
      const pat = normalizeScopeEntry(p);
      if (!pat) return false;
      if (pat.startsWith("*.")) {
        const base = pat.slice(2);
        return host === base || host.endsWith("." + base);
      }
      return host === pat;
    });
    if (!inScope) return { enabled: false };
  }
  return {
    enabled: true,
    canary: cfg.canary,
    tagged_canaries: cfg.tagged_canaries || {},
    auto_inject: cfg.auto_inject || [],
    ui_url: cfg.ui_url || "",
  };
}

// -------------------- message dispatch --------------------

// Watch for policies.json changes (Firefox refreshes managed storage
// when distribution/policies.json is rewritten). On a `reqlore browser`
// relaunch the bridge baseUrl / bootstrap token may both change; drop
// the cached config so the next request picks up the new values
// immediately instead of waiting for CFG_TTL_MS to expire.
try {
  browser.storage.onChanged.addListener((_changes, area) => {
    if (area === "managed" || area === "local") {
      cachedCfg = null;
      cachedAt = 0;
    }
  });
} catch (_) { /* older browsers without storage.onChanged */ }

browser.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || typeof msg !== "object") return;

  if (msg.type === "dom_hunter.requestConfig") {
    // Caller may explicitly pass {tabId, url} when it knows the
    // "inspected" target better than the message sender does. The
    // DevTools panel, popup and options page all run as extension
    // pages, so `sender.tab` is undefined and `sender.url` points at a
    // moz-extension:// page that will never match any user-defined
    // scope. Without these overrides every extension-page caller would
    // be told the tracer is off, even when it's on. See
    // tests/unit/test_dom_hunter.py::test_request_config_accepts_caller_tab_info.
    const tabId = (msg.tabId != null)
      ? msg.tabId
      : (sender.tab && sender.tab.id);
    const url = (typeof msg.url === "string" && msg.url)
      ? msg.url
      : ((sender.tab && sender.tab.url) || (sender.url || ""));
    return configForTab(tabId, url);
  }

  if (msg.type === "dom_hunter.getProjectConfig") {
    // Returns the raw bridge config (enabled, canary, scope, ui_url,
    // ...) WITHOUT applying per-tab scope filtering. Use this from
    // extension pages (panel/popup/options) to display the project
    // state itself, then call requestConfig with a tab override to
    // decide whether a specific tab is in scope.
    return fetchConfig();
  }

  if (msg.type === "dom_hunter.diagnose") {
    // Uncached probe -- panel/options use this to surface the actual
    // reason a getProjectConfig call returned null (HTTP status, network
    // error, missing token, ...).
    return diagnoseBridge();
  }

  if (msg.type === "dom_hunter.report") {
    return sendReport(msg.payload || {}, sender.tab && sender.tab.id);
  }

  if (msg.type === "dom_hunter.settings.get") {
    return getSettings();
  }

  if (msg.type === "dom_hunter.settings.set") {
    return setSettings(msg.settings || {}).then(() => ({ ok: true }));
  }

  if (msg.type === "dom_hunter.tabOff.get") {
    return getTabOffMap().then(m => ({ off: !!m[msg.tabId] }));
  }

  if (msg.type === "dom_hunter.tabOff.set") {
    return setTabOff(msg.tabId, !!msg.off).then(() => ({ ok: true }));
  }

  if (msg.type === "dom_hunter.reloadTab") {
    // Fallback used by the DevTools panel: extension pages can call
    // browser.tabs from the background but NOT from a devtools panel
    // (where `browser.tabs` is undefined regardless of the `tabs`
    // permission). The panel prefers devtools.inspectedWindow.reload();
    // this handler is only hit when that API is missing.
    return browser.tabs.reload(msg.tabId).then(() => ({ ok: true }))
                       .catch(e => ({ ok: false, error: String(e && e.message || e) }));
  }

  if (msg.type === "dom_hunter.findings.list") {
    return (async () => {
      try {
        const req = await bridgeRequest(
          "/dom-hunter/__bridge/findings.json?limit=" + (msg.limit || 50),
          { method: "GET" }
        );
        if (!req || !req.response || !req.response.ok) {
          return { findings: [], total: 0 };
        }
        return await req.response.json();
      } catch (_) { return { findings: [], total: 0 }; }
    })();
  }

  return undefined;
});

// -------------------- keyboard shortcuts --------------------

browser.commands.onCommand.addListener(async (name) => {
  if (name === "toggle-on-tab") {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id == null) return;
    const map = await getTabOffMap();
    const next = !map[tab.id];
    await setTabOff(tab.id, next);
    try { await browser.tabs.reload(tab.id); } catch (_) {}
    return;
  }
  if (name === "open-reqlore-findings") {
    const cfg = await fetchConfig();
    const url = (cfg && cfg.ui_url)
      || ((await getSettings()).baseUrl.replace(/\/+$/, "") + "/dom-hunter/");
    try { await browser.tabs.create({ url: url }); } catch (_) {}
    return;
  }
});

// Forget per-tab off state when the tab closes.
browser.tabs.onRemoved.addListener(async (tabId) => {
  const map = await getTabOffMap();
  if (map[tabId]) {
    delete map[tabId];
    await browser.storage.local.set({ [STORE_KEYS.tabOff]: map });
  }
});
