/* Reqlore DOM Hunter -- ISOLATED-world relay.
 *
 * Runs at document_start in the isolated world. Talks to the background
 * service worker to fetch the project config, then injects agent.js into
 * the MAIN world with the config attached. Also listens for window.postMessage
 * events from the agent and forwards them to the background.
 *
 * Accessibility note: this script never touches the inspected page's DOM
 * tree, focus, or ARIA. The only DOM interaction is appending a
 * <script src=agent.js> tag, then immediately removing it.
 */
(() => {
  "use strict";

  const RELAY_TAG = "__rqdomh_relay__";

  function injectAgent(cfg) {
    try {
      // Stash config where the MAIN-world agent can read it once.
      const code = "window.__dom_hunter_cfg__=" + JSON.stringify(cfg) + ";";
      const seed = document.createElement("script");
      seed.textContent = code;
      (document.head || document.documentElement).prepend(seed);
      seed.remove();

      const agent = document.createElement("script");
      agent.src = browser.runtime.getURL("content/agent.js");
      agent.async = false;
      (document.head || document.documentElement).prepend(agent);
      agent.addEventListener("load", () => agent.remove(), { once: true });
    } catch (_) { /* page may have nuked document.head */ }
  }

  // Forward messages from the MAIN-world agent to the background.
  window.addEventListener("message", (ev) => {
    if (ev.source !== window) return;
    const m = ev.data;
    if (!m || m.__rqdomh !== RELAY_TAG || !m.payload) return;
    try {
      browser.runtime.sendMessage({
        type: "dom_hunter.report",
        payload: m.payload,
      }).catch(() => { /* background may be restarting */ });
    } catch (_) {}
  }, false);

  // Ask the background for the current config; inject only if enabled.
  browser.runtime.sendMessage({ type: "dom_hunter.requestConfig" })
    .then((cfg) => {
      if (!cfg || !cfg.enabled || !cfg.canary) return;
      injectAgent(cfg);
    })
    .catch(() => { /* not configured yet */ });
})();
