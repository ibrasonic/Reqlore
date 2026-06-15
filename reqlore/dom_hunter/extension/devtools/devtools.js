/* DOM Hunter devtools bootstrap.
 * Registers a single DevTools panel labelled "DOM Hunter".
 * Firefox passes the inspected tab id to panel.js via
 * browser.devtools.inspectedWindow.tabId.
 *
 * Path resolution gotcha (per MDN devtools.panels.create):
 *   Firefox resolves iconPath/pagePath RELATIVE TO THE DEVTOOLS PAGE
 *   (/devtools/devtools.html), so bare "devtools/panel.html" 404s as
 *   /devtools/devtools/panel.html. Chromium/Safari resolve them as
 *   extension-root absolute. The portable form -- shown in MDN's own
 *   canonical example -- is a leading-slash path, which every engine
 *   treats as absolute from the extension root.
 */
"use strict";

browser.devtools.panels.create(
  "DOM Hunter",
  "/icons/icon.svg",
  "/devtools/panel.html"
).then(
  () => { /* registered */ },
  (err) => { console.warn("DOM Hunter panel registration failed:", err); }
);
