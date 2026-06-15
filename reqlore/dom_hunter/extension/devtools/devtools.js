/* DOM Hunter devtools bootstrap.
 * Registers a single DevTools panel labelled "DOM Hunter".
 * Firefox passes the inspected tab id to panel.js via
 * browser.devtools.inspectedWindow.tabId.
 */
"use strict";

browser.devtools.panels.create(
  "DOM Hunter",
  "icons/icon.svg",
  browser.runtime.getURL("devtools/panel.html")
).then(
  () => { /* registered */ },
  (err) => { console.warn("DOM Hunter panel registration failed:", err); }
);
