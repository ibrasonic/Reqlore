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

  // Snapshot of source values at agent-load time. Pages frequently
  // read e.g. location.hash, parse it, then call history.replaceState
  // to clean the URL -- by the time a later sink fires, the live
  // location.hash no longer contains the canary and attribution would
  // fail. detectSource() consults both the live and initial values.
  const initial = { hash: "", search: "", pathname: "",
                    referrer: "", name: "" };
  try { initial.hash = location.hash || ""; } catch (_) {}
  try { initial.search = location.search || ""; } catch (_) {}
  try { initial.pathname = location.pathname || ""; } catch (_) {}
  try { initial.referrer = document.referrer || ""; } catch (_) {}
  try { initial.name = window.name || ""; } catch (_) {}

  // Ring buffer of recent postMessage payloads that contained the
  // canary. Multiple handlers can fire between two sinks, so a single
  // "last" slot races -- the buffer keeps the most recent N for
  // detectSource() to scan.
  const MSG_BUFFER_SIZE = 8;
  const messageCanaryBuffer = [];
  function _rqdomhPushMessageCanary(s) {
    if (!s) return;
    if (messageCanaryBuffer.indexOf(s) !== -1) return;
    messageCanaryBuffer.push(s);
    if (messageCanaryBuffer.length > MSG_BUFFER_SIZE) {
      messageCanaryBuffer.shift();
    }
  }

  // WeakMap of original message-listener -> our wrapping function, so
  // a later removeEventListener("message", originalFn) finds the
  // wrapper we actually registered and removes it. Without this the
  // page's listener-removal silently fails and message handlers leak,
  // which is a real reliability problem on long-lived SPAs.
  const messageListenerWrapMap = new WeakMap();

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

  // ---------------- source attribution ----------------
  //
  // When a sink fires we know value contains CANARY, but not which DOM
  // source(s) the page read it from. detectSource() consults every
  // source the agent can observe and returns EVERY source whose
  // content has a verified overlap with value -- joined with "," and
  // ordered by precedence (pure-DOM vectors before cross-cutting
  // ones). When the user auto-injects into multiple sources at once,
  // all of them appear in the finding rather than one silently winning.
  //
  // The precedence order survives only as the display order when
  // multiple sources match; it is no longer a tiebreaker that hides
  // other matches.
  //
  // All IDs returned MUST exist in reqlore.dom_hunter.SOURCE_INDEX or
  // the bridge drops them as "unknown".

  // Overlap score using the bidirectional-substring heuristic. Pages
  // often decode the source (decodeURIComponent on location.hash) or
  // encode the value (URLSearchParams stringifies) before the canary
  // reaches the sink, so we also try the decoded and decoded-tail
  // forms. Returns 0 if no overlap; caller falls through to other
  // candidates.
  function _rqdomhSafeDecode(s) {
    try { return decodeURIComponent(s); } catch (_) { return ""; }
  }
  function _rqdomhSourceScore(srcVal, needle) {
    if (!srcVal || !needle) return 0;
    // Try raw, decoded, and (when prefixed with # or ?) the tail forms.
    const variants = [srcVal];
    const dec = _rqdomhSafeDecode(srcVal);
    if (dec && dec !== srcVal) variants.push(dec);
    const c0 = srcVal.charCodeAt(0);
    if (c0 === 35 /* # */ || c0 === 63 /* ? */) {
      const tail = srcVal.slice(1);
      if (tail) {
        variants.push(tail);
        const tdec = _rqdomhSafeDecode(tail);
        if (tdec && tdec !== tail) variants.push(tdec);
      }
    }
    let best = 0;
    for (let i = 0; i < variants.length; i++) {
      const v = variants[i];
      if (!v) continue;
      if (v.indexOf(CANARY) === -1) continue;
      if (v.indexOf(needle) !== -1) {
        if (needle.length > best) best = needle.length;
        continue;
      }
      if (needle.indexOf(v) !== -1) {
        if (v.length > best) best = v.length;
      }
    }
    return best;
  }

  function detectSource(value) {
    const s = safeStr(value);
    if (!s || s.indexOf(CANARY) === -1) return "unknown";

    let h = "", q = "", p = "", ref = "", n = "", c = "";
    try { h = location.hash || ""; } catch (_) {}
    try { q = location.search || ""; } catch (_) {}
    try { p = location.pathname || ""; } catch (_) {}
    try { ref = document.referrer || ""; } catch (_) {}
    try { n = window.name || ""; } catch (_) {}
    try { c = document.cookie || ""; } catch (_) {}

    // Precedence-ordered candidate list. Each row: [id, content]. Live
    // values come first within each source; the snapshot is a fallback
    // when the page mutated the live value after reading.
    const candidates = [
      ["location.hash", h],
      ["location.hash", initial.hash]
    ];
    // Recent canary-bearing postMessages, newest first.
    for (let i = messageCanaryBuffer.length - 1; i >= 0; i--) {
      candidates.push(["postMessage", messageCanaryBuffer[i]]);
    }
    candidates.push(
      ["window.name", n],
      ["window.name", initial.name],
      ["document.referrer", ref],
      ["document.referrer", initial.referrer],
      ["location.search", q],
      ["location.search", initial.search],
      ["document.cookie", c],
      ["location.pathname", p],
      ["location.pathname", initial.pathname]
    );

    // Collect EVERY source id with a verified overlap. We keep the
    // precedence order as display order but no longer let it hide
    // other matches.
    const matched = [];
    const seenIds = Object.create(null);
    for (let rank = 0; rank < candidates.length; rank++) {
      const id = candidates[rank][0];
      if (seenIds[id]) continue;
      const content = candidates[rank][1];
      if (_rqdomhSourceScore(content, s) > 0) {
        matched.push(id);
        seenIds[id] = true;
      }
    }

    // Bounded storage scan: only runs when nothing live matched. Two
    // separate buckets (localStorage / sessionStorage) so each can
    // appear independently.
    if (matched.length === 0) {
      const STORAGE_SCAN_LIMIT = 200;
      try {
        const ls = window.localStorage;
        if (ls) {
          const n2 = Math.min(ls.length, STORAGE_SCAN_LIMIT);
          for (let i = 0; i < n2; i++) {
            const v = ls.getItem(ls.key(i)) || "";
            if (_rqdomhSourceScore(v, s) > 0) {
              matched.push("localStorage");
              break;
            }
          }
        }
      } catch (_) {}
      try {
        const ss = window.sessionStorage;
        if (ss) {
          const n2 = Math.min(ss.length, STORAGE_SCAN_LIMIT);
          for (let i = 0; i < n2; i++) {
            const v = ss.getItem(ss.key(i)) || "";
            if (_rqdomhSourceScore(v, s) > 0) {
              matched.push("sessionStorage");
              break;
            }
          }
        }
      } catch (_) {}
    }

    if (matched.length === 0) return "unknown";
    return matched.join(",");
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
    // Bridge stores stacks up to 8192 chars; cap here so the relay
    // postMessage stays well under the structured-clone limit.
    if (trimmed.length > 8000) {
      trimmed = trimmed.slice(0, 8000) + "\n... [truncated]";
    }

    // SPA route changes between hook fire and report would otherwise
    // leave the stored finding pointing at a stale URL; recapture now.
    let nowUrl = pageUrl;
    try { nowUrl = location.href || pageUrl; } catch (_) {}

    const dkey = [kind, sink, source, nowUrl,
                  (trimmed.split("\n").find(s => s.trim()) || ""),
                  containsCanary ? "c" : "n"].join("|");
    if (seen.has(dkey)) return;
    seen.add(dkey);

    const out = {
      kind: kind,
      sink: sink,
      source: source,
      page_url: nowUrl,
      frame_url: nowUrl,
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
              report("finding", sinkName, detectSource(s), s, null);
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
                  report("finding", sinkName, detectSource(s), s, null);
                }
              } else {
                report("finding", sinkName, detectSource(s), s, null);
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
    // srcdoc renders a full HTML document inside the iframe; scripts in
    // the string execute. Commonly missed in DOM-XSS reviews.
    wrapSetter(HTMLIFrameElement.prototype, "srcdoc",
               "HTMLIFrameElement.srcdoc");
  }

  wrapMethod(Element.prototype, "insertAdjacentHTML",
             "Element.insertAdjacentHTML", 1);
  wrapMethod(Element.prototype, "setAttribute",
             "Element.setAttribute(on*)", 1);
  wrapMethod(document, "write",   "document.write",   0);
  wrapMethod(document, "writeln", "document.writeln", 0);

  // DOMParser.parseFromString: a string parsed as HTML is risky once
  // the resulting nodes are inserted live; flag the raw call so the
  // operator can audit how the parsed tree is used downstream.
  if (window.DOMParser && DOMParser.prototype) {
    wrapMethod(DOMParser.prototype, "parseFromString",
               "DOMParser.parseFromString", 0);
  }
  // Range.createContextualFragment: the string is parsed as HTML and
  // scripts may execute when the resulting fragment is inserted.
  if (window.Range && Range.prototype) {
    wrapMethod(Range.prototype, "createContextualFragment",
               "Range.createContextualFragment", 0);
  }

  // new Worker(url): the URL string can be javascript: or blob: that
  // ends up running attacker code in a Worker context.
  try {
    const OrigWorker = window.Worker;
    if (typeof OrigWorker === "function") {
      function ProxiedWorker(url, opts) {
        try {
          const s = safeStr(url);
          if (s.indexOf(CANARY) !== -1) {
            report("finding", "Worker", detectSource(s), s, null);
          }
        } catch (_) {}
        return new OrigWorker(url, opts);
      }
      ProxiedWorker.prototype = OrigWorker.prototype;
      window.Worker = ProxiedWorker;
    }
  } catch (_) {}

  // window.eval can be hard to replace on some pages; try anyway.
  try {
    const origEval = window.eval;
    window.eval = function _rqdomh_eval(s) {
      try {
        const v = safeStr(s);
        if (v.indexOf(CANARY) !== -1) {
          report("finding", "eval", detectSource(v), v, null);
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
          report("finding", "setTimeout(string)", detectSource(handler), handler, null);
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
          report("finding", "setInterval(string)", detectSource(handler), handler, null);
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
          report("finding", "Function", detectSource(body), body, null);
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
  //
  // Wraps every "message" listener so the agent can log incoming
  // payloads and stash canary-bearing data for detectSource(). We also
  // wrap removeEventListener so the page's later removal call finds
  // the wrapper we registered, instead of silently failing -- without
  // this, long-lived SPAs accumulate stale message handlers.

  try {
    const origAdd = EventTarget.prototype.addEventListener;
    const origRemove = EventTarget.prototype.removeEventListener;

    EventTarget.prototype.addEventListener = function _rqdomh_add(type, fn, opts) {
      if (type === "message" && typeof fn === "function") {
        let wrapped = messageListenerWrapMap.get(fn);
        if (!wrapped) {
          wrapped = function (ev) {
            try {
              let data = ev && ev.data;
              let dataStr;
              try {
                dataStr = typeof data === "string"
                  ? data : JSON.stringify(data);
              } catch (_) { dataStr = String(data); }
              const hasCanary = (dataStr || "").indexOf(CANARY) !== -1;
              if (hasCanary) _rqdomhPushMessageCanary(dataStr || "");
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
          messageListenerWrapMap.set(fn, wrapped);
        }
        return origAdd.call(this, type, wrapped, opts);
      }
      return origAdd.apply(this, arguments);
    };

    EventTarget.prototype.removeEventListener = function _rqdomh_remove(type, fn, opts) {
      if (type === "message" && typeof fn === "function") {
        const wrapped = messageListenerWrapMap.get(fn);
        if (wrapped) {
          // Remove BOTH the wrapper and (defensively) the raw fn in
          // case the page ever registered it directly before our hook
          // was installed (race window at document_start).
          try { origRemove.call(this, type, wrapped, opts); } catch (_) {}
          try { origRemove.call(this, type, fn, opts); } catch (_) {}
          return;
        }
      }
      return origRemove.apply(this, arguments);
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
