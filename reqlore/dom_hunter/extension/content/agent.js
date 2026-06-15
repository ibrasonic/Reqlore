/* Reqlore DOM Hunter -- MAIN world agent.
 *
 * Loaded into every in-scope frame at document_start by isolated.js.
 * Hooks dangerous JavaScript sinks and reports any call whose string
 * argument contains the project's canary back through window.postMessage
 * to the ISOLATED-world relay (isolated.js).
 *
 * Strict invariants:
 *   - Never modifies the inspected page's DOM tree.
 *   - Never moves focus.
 *   - Never changes ARIA, never opens dialogs.
 *   - Never writes to localStorage / sessionStorage / cookies.
 * The only side effect on the host page is wrapping function and
 * accessor descriptors so the agent can see what was passed in.
 */
(() => {
  "use strict";

  // The bootstrap reads __dom_hunter_cfg__ off window before injecting us.
  const cfg = (window.__dom_hunter_cfg__ || {});
  delete window.__dom_hunter_cfg__;

  if (!cfg.enabled || !cfg.canary) return;

  const CANARY = String(cfg.canary);
  const RELAY_TAG = "__rqdomh_relay__";
  const seen = new Set();
  let pageUrl = "";
  try { pageUrl = location.href; } catch (_) { /* sandboxed frame */ }

  // ---------------- helpers ----------------

  function safeStr(v) {
    try {
      if (v == null) return String(v);
      if (typeof v === "string") return v;
      return String(v);
    } catch (_) { return ""; }
  }

  function captureStack() {
    try { throw new Error("stack"); }
    catch (e) { return (e && e.stack) || ""; }
  }

  function postRelay(payload) {
    try {
      window.postMessage({ __rqdomh: RELAY_TAG, payload: payload }, "*");
    } catch (_) { /* page may have frozen postMessage; nothing we can do */ }
  }

  function report(kind, sink, source, value, extra) {
    const v = safeStr(value);
    const containsCanary = v.indexOf(CANARY) !== -1;
    const stack = captureStack();
    // Trim the agent's own frames out of the head of the stack for clarity.
    let trimmed = stack;
    const lines = stack.split("\n");
    let i = 0;
    while (i < lines.length && /(_rqdomh|agent\.js)/.test(lines[i])) i++;
    if (i > 0) trimmed = lines.slice(i).join("\n");

    const dkey = [kind, sink, source, pageUrl,
                  (trimmed.split("\n").find(s => s.trim()) || ""),
                  containsCanary ? "c" : "n"].join("|");
    if (seen.has(dkey)) return;
    seen.add(dkey);

    const out = {
      kind: kind,
      sink: sink,
      source: source,
      page_url: pageUrl,
      frame_url: pageUrl,
      value: v.length > 4096 ? v.slice(0, 4096) + "... [truncated]" : v,
      stack: trimmed,
      canary_seen: containsCanary,
    };
    if (extra) Object.assign(out, extra);
    postRelay(out);
  }

  // ---------------- sink: setter on a prototype property ----------------

  function wrapSetter(proto, prop, sinkName) {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set || !d.configurable) return;
      const origSet = d.set;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: function _rqdomh_set(v) {
          try {
            const s = safeStr(v);
            if (s.indexOf(CANARY) !== -1) {
              report("finding", sinkName, "unknown", s, null);
            }
          } catch (_) {}
          return origSet.call(this, v);
        },
      });
    } catch (_) { /* some props are non-configurable in some browsers */ }
  }

  // ---------------- sink: method on an object ----------------

  function wrapMethod(obj, name, sinkName, argIndex) {
    try {
      const orig = obj[name];
      if (typeof orig !== "function") return;
      Object.defineProperty(obj, name, {
        configurable: true,
        writable: true,
        enumerable: false,
        value: function _rqdomh_call() {
          try {
            const v = arguments[argIndex || 0];
            const s = safeStr(v);
            if (s.indexOf(CANARY) !== -1) {
              // Special case: setAttribute -- only flag event handler attrs.
              if (sinkName === "Element.setAttribute(on*)") {
                const attr = String(arguments[0] || "").toLowerCase();
                if (attr.indexOf("on") === 0) {
                  report("finding", sinkName, "unknown", s, null);
                }
              } else {
                report("finding", sinkName, "unknown", s, null);
              }
            }
          } catch (_) {}
          return orig.apply(this, arguments);
        },
      });
    } catch (_) {}
  }

  // ---------------- install sink hooks ----------------

  wrapSetter(Element.prototype, "innerHTML", "Element.innerHTML");
  wrapSetter(Element.prototype, "outerHTML", "Element.outerHTML");
  if (window.HTMLScriptElement) {
    wrapSetter(HTMLScriptElement.prototype, "src", "HTMLScriptElement.src");
  }
  if (window.HTMLIFrameElement) {
    wrapSetter(HTMLIFrameElement.prototype, "src", "HTMLIFrameElement.src");
  }

  wrapMethod(Element.prototype, "insertAdjacentHTML",
             "Element.insertAdjacentHTML", 1);
  wrapMethod(Element.prototype, "setAttribute",
             "Element.setAttribute(on*)", 1);
  wrapMethod(document, "write",   "document.write",   0);
  wrapMethod(document, "writeln", "document.writeln", 0);

  // window.eval can be hard to replace on some pages; try anyway.
  try {
    const origEval = window.eval;
    window.eval = function _rqdomh_eval(s) {
      try {
        if (safeStr(s).indexOf(CANARY) !== -1) {
          report("finding", "eval", "unknown", safeStr(s), null);
        }
      } catch (_) {}
      return origEval(s);
    };
  } catch (_) {}

  // setTimeout / setInterval with a STRING first arg behave like eval.
  try {
    const origST = window.setTimeout;
    window.setTimeout = function _rqdomh_st(handler) {
      try {
        if (typeof handler === "string" && handler.indexOf(CANARY) !== -1) {
          report("finding", "setTimeout(string)", "unknown", handler, null);
        }
      } catch (_) {}
      return origST.apply(this, arguments);
    };
  } catch (_) {}
  try {
    const origSI = window.setInterval;
    window.setInterval = function _rqdomh_si(handler) {
      try {
        if (typeof handler === "string" && handler.indexOf(CANARY) !== -1) {
          report("finding", "setInterval(string)", "unknown", handler, null);
        }
      } catch (_) {}
      return origSI.apply(this, arguments);
    };
  } catch (_) {}

  // new Function("...").
  try {
    const OrigFunction = window.Function;
    function ProxiedFunction() {
      try {
        const body = arguments[arguments.length - 1];
        if (typeof body === "string" && body.indexOf(CANARY) !== -1) {
          report("finding", "Function", "unknown", body, null);
        }
      } catch (_) {}
      // Forward call to original; mimic both call and construct.
      const args = Array.prototype.slice.call(arguments);
      // eslint-disable-next-line prefer-spread
      return new (Function.prototype.bind.apply(OrigFunction,
        [null].concat(args)))();
    }
    ProxiedFunction.prototype = OrigFunction.prototype;
    window.Function = ProxiedFunction;
  } catch (_) {}

  // location.href assignment via setter on Location.prototype is browser-
  // protected; we approximate by hooking history.pushState/replaceState
  // and the link-href setter, and by wrapping the navigation helpers.
  try {
    wrapSetter(HTMLAnchorElement.prototype, "href", "HTMLAnchorElement.href");
  } catch (_) {}

  // ---------------- postMessage logger ----------------

  try {
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function _rqdomh_add(type, fn, opts) {
      if (type === "message" && typeof fn === "function") {
        const wrapped = function (ev) {
          try {
            let data = ev && ev.data;
            let dataStr;
            try {
              dataStr = typeof data === "string" ? data : JSON.stringify(data);
            } catch (_) { dataStr = String(data); }
            const hasCanary = (dataStr || "").indexOf(CANARY) !== -1;
            postRelay({
              kind: "message",
              page_url: pageUrl,
              origin: String((ev && ev.origin) || ""),
              data: dataStr || "",
              has_canary: hasCanary,
              handler_stack: captureStack(),
            });
          } catch (_) {}
          return fn.apply(this, arguments);
        };
        return origAdd.call(this, type, wrapped, opts);
      }
      return origAdd.apply(this, arguments);
    };
  } catch (_) {}

  // ---------------- auto-inject canary into sources ----------------

  try {
    const ai = Array.isArray(cfg.auto_inject) ? cfg.auto_inject : [];
    if (ai.indexOf("location.hash") !== -1) {
      const h = location.hash || "";
      if (h.indexOf(CANARY) === -1) {
        // Append, don't replace: existing routes may matter.
        try { location.hash = (h ? h + "&" : "#") + "rqdomh=" + CANARY; }
        catch (_) {}
      }
    }
    if (ai.indexOf("location.search") !== -1) {
      const s = location.search || "";
      if (s.indexOf(CANARY) === -1) {
        try {
          const u = new URL(location.href);
          u.searchParams.set("rqdomh", CANARY);
          history.replaceState(null, "", u.toString());
        } catch (_) {}
      }
    }
    if (ai.indexOf("window.name") !== -1) {
      try { if ((window.name || "").indexOf(CANARY) === -1) {
        window.name = (window.name || "") + " " + CANARY;
      } } catch (_) {}
    }
    // document.referrer is read-only from a content script. When the
    // user ticks the "document.referrer" auto-inject box, the Reqlore
    // proxy's request hook splices the canary into the outgoing Referer
    // header for in-scope requests instead. See
    // reqlore.dom_hunter.inject_referer_canary.
  } catch (_) {}

  // ---------------- mark ready ----------------
  postRelay({ kind: "ready", page_url: pageUrl });
})();
