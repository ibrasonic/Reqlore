/* Reqlore — progressive enhancement only.
   The app must work fully with JS disabled. This file adds:
   - keyboard ? to open Help
   - live-region announcement helper
   - optional audio cues for flash messages (when enabled in Settings)
*/
(function () {
  "use strict";

  function announce(msg) {
    var live = document.getElementById("sr-live");
    if (!live) return;
    live.textContent = "";
    setTimeout(function () { live.textContent = msg; }, 50);
  }

  document.addEventListener("keydown", function (e) {
    if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
    if (e.key === "?" && !e.ctrlKey && !e.altKey && !e.metaKey) {
      e.preventDefault();
      window.location.href = "/help/";
    }
  });

  // Focus restoration after a form submit / page navigation.
  //
  // The default browser behaviour after a GET / POST form submit is
  // to load the response document with focus parked on <body> — so a
  // screen reader starts re-reading from the top of the page, and a
  // sighted-keyboard user has to tab back into the data they were
  // editing. To preserve position across the whole tool we use
  // sessionStorage as a one-shot baton:
  //
  //   * On submit of any <form>, stash {path, selector, ts} keyed
  //     under a single well-known storage entry. The selector comes
  //     from the form's `data-focus-after-submit` attribute when
  //     present; otherwise we default to "#main" (every page has
  //     <main id="main" tabindex="-1">), which still keeps the SR
  //     inside the page region instead of at <body>.
  //   * On every page load, read the entry. If it matches the
  //     current pathname AND is fresh (under 30 s), find the target,
  //     give it tabindex="-1" if it has no natural focus, and
  //     focus({preventScroll: true}) — preserving the browser's own
  //     restored scroll position so we don't yank the viewport.
  //   * The entry is cleared after one consumption so a later
  //     unrelated navigation isn't hijacked.
  //
  // To opt a specific form's landing target in, add
  //   <form ... data-focus-after-submit="#some-id">
  // (or any CSS selector). Existing forms without the attribute
  // continue to land on <main> as before.
  var FOCUS_KEY = "reqloreFocusAfterNav";
  function stashFocusTarget(selector) {
    try {
      sessionStorage.setItem(FOCUS_KEY, JSON.stringify({
        path: window.location.pathname,
        sel: selector || "#main",
        ts: Date.now()
      }));
    } catch (_) { /* sessionStorage unavailable: best-effort, drop */ }
  }
  // Expose for the auto-refresh / Refresh-now paths below.
  window.Reqlore = window.Reqlore || {};
  window.Reqlore.stashFocusTarget = stashFocusTarget;

  document.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!f || f.tagName !== "FORM") return;
    var sel = f.getAttribute("data-focus-after-submit") || "#main";
    // For GET forms the post-submit URL changes (filters appended);
    // for POST forms the action's pathname is what we'll land on.
    // Either way pathname == the form's action pathname when we get
    // there, so we use that for the matching key.
    var path;
    try {
      path = new URL(f.action || window.location.href, window.location.origin).pathname;
    } catch (_) {
      path = window.location.pathname;
    }
    try {
      sessionStorage.setItem(FOCUS_KEY, JSON.stringify({
        path: path, sel: sel, ts: Date.now()
      }));
    } catch (_) { /* ignore */ }
  });

  // On load: consume the stashed target if it's for this page.
  (function () {
    var raw;
    try { raw = sessionStorage.getItem(FOCUS_KEY); } catch (_) { return; }
    if (!raw) return;
    var data;
    try { data = JSON.parse(raw); } catch (_) {
      try { sessionStorage.removeItem(FOCUS_KEY); } catch (_) {}
      return;
    }
    try { sessionStorage.removeItem(FOCUS_KEY); } catch (_) {}
    if (!data || data.path !== window.location.pathname) return;
    if (typeof data.ts === "number" && Date.now() - data.ts > 30000) return;
    var target = null;
    try { target = document.querySelector(data.sel); } catch (_) { return; }
    if (!target) return;
    if (!target.hasAttribute("tabindex") &&
        !/^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(target.tagName)) {
      target.setAttribute("tabindex", "-1");
    }
    // requestAnimationFrame so the focus call lands after the browser
    // has settled the layout — without this, some browsers ignore the
    // focus on a freshly-parsed <table>.
    requestAnimationFrame(function () {
      try { target.focus({ preventScroll: true }); }
      catch (_) { target.focus(); }
    });
  })();

  // Audio cues from flash messages (only when ul.flashes has data-cues="1").
  var flashes = document.querySelector("ul.flashes[data-cues='1']");
  if (flashes) {
    var first = flashes.querySelector("li[data-cue]");
    if (first) {
      var cat = first.getAttribute("data-cue") || "ok";
      var map = { ok: "ok", warn: "warn", err: "error" };
      var name = map[cat] || "ok";
      try {
        var a = new Audio("/cues/" + name + ".wav");
        a.volume = 0.5;
        a.play().catch(function () { /* autoplay blocked; silent */ });
      } catch (_) { /* ignore */ }
    }
  }

  // Expose for inline-template hooks if ever needed
  window.Reqlore = window.Reqlore || {};
  window.Reqlore.announce = announce;

  // Repeater: single toggle that flips the response (headers + body)
  // between Raw and URL-decoded views. Both versions are rendered
  // server-side; we just flip [hidden] on [data-resp-view] elements.
  var respToggle = document.querySelector("[data-resp-view-toggle]");
  if (respToggle) {
    respToggle.addEventListener("click", function () {
      var decoded = respToggle.getAttribute("aria-pressed") !== "true";
      respToggle.setAttribute("aria-pressed", decoded ? "true" : "false");
      respToggle.textContent = decoded ? "Raw view" : "URL-decode view";
      var want = decoded ? "decoded" : "raw";
      document.querySelectorAll("[data-resp-view]").forEach(function (el) {
        el.hidden = (el.getAttribute("data-resp-view") !== want);
      });
      announce("Response view: " + (decoded ? "URL-decoded" : "raw"));
    });
  }

  // Proxy: auto-submit the intercept checkbox so the user doesn't need
  // a separate Apply button. The <noscript> fallback keeps it usable
  // without JS.
  var iCb = document.querySelector("[data-intercept-checkbox]");
  if (iCb) {
    iCb.addEventListener("change", function () {
      iCb.form.submit();
    });
  }

  // Proxy queue: when intercept is ON, poll a cheap JSON endpoint and
  // reload the page ONLY when the held-count changes. This avoids a
  // chatty meta-refresh that re-announces the whole page to screen
  // readers every few seconds.
  var watch = document.querySelector("[data-intercept-watch]");
  if (watch && watch.getAttribute("data-intercept-on") === "1") {
    var baseline = parseInt(watch.getAttribute("data-intercept-count") || "0", 10);
    var poll = function () {
      fetch("/proxy/intercept/count", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (j) {
          if (!j) return;
          if (j.count !== baseline) {
            announce("Intercept queue changed (" + j.count + ").");
            window.location.reload();
          }
        })
        .catch(function () { /* network blip; try again next tick */ });
    };
    setInterval(poll, 2000);
  }

  // History: row Actions menu button (WAI-ARIA APG Menu Button pattern).
  // No JS: button stays [hidden]; the <ul> renders as a flat list of
  // links / inline submit buttons (each <form> still submits on click).
  // With JS: button is shown, list is hidden until activated. We add
  // role=menu / menuitem, roving focus with arrow keys, Home/End, Esc,
  // a Tab focus-trap, click-outside-to-close, and 500ms type-ahead.
  // Menu items can be either <a href> (used by History) or
  // <form><button type=submit></form> (used by the Proxy held-queue,
  // which needs CSRF-protected POSTs for Forward / Drop / Send to ...).
  (function () {
    var widgets = document.querySelectorAll("[data-row-actions]");
    if (!widgets.length) return;
    var openWidget = null;

    function items(w) {
      return Array.prototype.slice.call(
        w.querySelectorAll('[role="menuitem"]'));
    }

    function openFor(w, where) {
      if (openWidget && openWidget !== w) closeFor(openWidget, false);
      var btn = w.querySelector(".row-actions-toggle");
      var list = w.querySelector(".row-actions-list");
      if (!btn || !list) return;
      btn.setAttribute("aria-expanded", "true");
      list.hidden = false;
      openWidget = w;
      var all = items(w);
      if (!all.length) return;
      var idx = where === "last" ? all.length - 1
              : (typeof where === "number" ? where : 0);
      if (idx < 0 || idx >= all.length) idx = 0;
      all[idx].focus();
    }

    function closeFor(w, returnFocus) {
      var btn = w.querySelector(".row-actions-toggle");
      var list = w.querySelector(".row-actions-list");
      if (!btn || !list) return;
      if (btn.getAttribute("aria-expanded") !== "true") return;
      btn.setAttribute("aria-expanded", "false");
      list.hidden = true;
      if (returnFocus) btn.focus();
      if (openWidget === w) openWidget = null;
    }

    function focusBy(w, delta) {
      var all = items(w);
      if (!all.length) return;
      var cur = all.indexOf(document.activeElement);
      if (cur < 0) cur = 0;
      all[(cur + delta + all.length) % all.length].focus();
    }

    function focusEdge(w, which) {
      var all = items(w);
      if (!all.length) return;
      all[which === "first" ? 0 : all.length - 1].focus();
    }

    var typeBuf = "", typeTimer = null;
    function typeAhead(w, ch) {
      clearTimeout(typeTimer);
      typeBuf += ch.toLowerCase();
      typeTimer = setTimeout(function () { typeBuf = ""; }, 500);
      var all = items(w);
      var start = Math.max(0, all.indexOf(document.activeElement));
      for (var i = 1; i <= all.length; i++) {
        var el = all[(start + i) % all.length];
        if ((el.textContent || "").trim().toLowerCase().indexOf(typeBuf) === 0) {
          el.focus();
          return;
        }
      }
    }

    widgets.forEach(function (w) {
      var btn = w.querySelector(".row-actions-toggle");
      var list = w.querySelector(".row-actions-list");
      if (!btn || !list) return;

      // Upgrade the markup to the menu pattern.
      w.setAttribute("data-enhanced", "");
      btn.hidden = false;
      list.hidden = true;
      list.setAttribute("role", "menu");
      list.querySelectorAll("li").forEach(function (li) {
        li.setAttribute("role", "none");
      });
      list.querySelectorAll('li > a, li > form > button[type="submit"]').forEach(function (el) {
        el.setAttribute("role", "menuitem");
        el.setAttribute("tabindex", "-1");
      });

      btn.addEventListener("click", function (ev) {
        ev.preventDefault();
        if (btn.getAttribute("aria-expanded") === "true") {
          closeFor(w, true);
        } else {
          openFor(w, 0);
        }
      });

      btn.addEventListener("keydown", function (ev) {
        if (ev.key === "ArrowDown" || ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault(); openFor(w, 0);
        } else if (ev.key === "ArrowUp") {
          ev.preventDefault(); openFor(w, "last");
        }
      });

      list.addEventListener("keydown", function (ev) {
        if (btn.getAttribute("aria-expanded") !== "true") return;
        switch (ev.key) {
          case "ArrowDown": ev.preventDefault(); focusBy(w, +1); break;
          case "ArrowUp":   ev.preventDefault(); focusBy(w, -1); break;
          case "Home":      ev.preventDefault(); focusEdge(w, "first"); break;
          case "End":       ev.preventDefault(); focusEdge(w, "last");  break;
          case "Escape":    ev.preventDefault(); closeFor(w, true); break;
          case "Tab":
            // Strict focus trap: keep focus inside the menu until the
            // user presses Esc or activates a menuitem.
            ev.preventDefault();
            focusBy(w, ev.shiftKey ? -1 : +1);
            break;
          default:
            if (ev.key.length === 1 && /\S/.test(ev.key) &&
                !ev.ctrlKey && !ev.altKey && !ev.metaKey) {
              typeAhead(w, ev.key);
            }
        }
      });
    });

    // Click outside any open menu closes it (no focus return per APG).
    document.addEventListener("mousedown", function (ev) {
      if (!openWidget) return;
      if (!openWidget.contains(ev.target)) closeFor(openWidget, false);
    });

    window.Reqlore = window.Reqlore || {};
    window.Reqlore.closeRowActionsFor = function (el, returnFocus) {
      var w = el.closest && el.closest("[data-row-actions]");
      if (w) closeFor(w, !!returnFocus);
    };
  })();

  // History: 2-step Comparer pick.
  // No JS: each row's "Compare A" link goes straight to /comparer?from_a=<id>.
  // With JS: first click on any row records that row as A and re-labels
  // every other row's link to "Compare B"; the second click (on a different
  // row) navigates to /comparer?from_a=<A>&from_b=<B>. Clicking the row
  // that holds A again clears the selection.
  (function () {
    var picks = document.querySelectorAll("a.cmp-pick");
    if (!picks.length) return;
    var table = document.getElementById("hist-table");
    var baseUrl = (table && table.getAttribute("data-comparer-url")) || "/comparer/";
    var status = document.getElementById("cmp-status");
    var KEY = "reqloreCompareA";

    function setStatus(msg) {
      if (!status) return;
      status.textContent = msg || "";
      status.hidden = !msg;
    }

    function relabel() {
      var a = sessionStorage.getItem(KEY);
      picks.forEach(function (el) {
        var hid = el.getAttribute("data-hid");
        var labelA = el.getAttribute("data-label-a") || "Compare A";
        var labelB = el.getAttribute("data-label-b") || "Compare B";
        if (a && a === hid) {
          el.textContent = "Compare (A picked)";
          el.setAttribute("aria-label",
            "Request #" + hid + " is picked as A. Click again to clear, or pick another row as B.");
        } else if (a) {
          el.textContent = labelB;
          el.setAttribute("aria-label", "Compare with A (A is request #" + a + ")");
        } else {
          el.textContent = labelA;
          el.removeAttribute("aria-label");
        }
      });
      if (a) {
        setStatus("Compare A = #" + a + ". Click Compare B on another row to open the comparer.");
      } else {
        setStatus("");
      }
    }

    picks.forEach(function (el) {
      el.addEventListener("click", function (ev) {
        var hid = el.getAttribute("data-hid");
        var a = sessionStorage.getItem(KEY);
        if (!a) {
          ev.preventDefault();
          sessionStorage.setItem(KEY, hid);
          relabel();
          announce("Picked request #" + hid +
            " as A. Click Compare on another row to pick B.");
          if (window.Reqlore && window.Reqlore.closeRowActionsFor) {
            window.Reqlore.closeRowActionsFor(el, true);
          }
          return;
        }
        if (a === hid) {
          ev.preventDefault();
          sessionStorage.removeItem(KEY);
          relabel();
          announce("Cleared compare A.");
          if (window.Reqlore && window.Reqlore.closeRowActionsFor) {
            window.Reqlore.closeRowActionsFor(el, true);
          }
          return;
        }
        ev.preventDefault();
        sessionStorage.removeItem(KEY);
        var sep = baseUrl.indexOf("?") >= 0 ? "&" : "?";
        window.location.href = baseUrl + sep +
          "from_a=" + encodeURIComponent(a) +
          "&from_b=" + encodeURIComponent(hid);
      });
    });

    relabel();
  })();

  // Intruder "New attack" page: progressive disclosure of the source-
  // specific input groups. The server pre-renders every group with the
  // `hidden` attribute on all but the one matching `form.source` so
  // JS-off users still get a usable form (see <noscript> fallback in
  // the template). With JS we additionally toggle `hidden` when the
  // source dropdown changes — `hidden` removes the element from the
  // accessibility tree per spec, so screen readers don't get the
  // noisy alternatives either.
  (function () {
    var sel = document.querySelector("[data-source-select]");
    if (!sel) return;
    var groups = document.querySelectorAll("[data-source-group]");
    if (!groups.length) return;
    function apply(src) {
      groups.forEach(function (g) {
        var keys = (g.getAttribute("data-source-group") || "").split(/\s+/);
        g.hidden = keys.indexOf(src) === -1;
      });
    }
    apply(sel.value);
    sel.addEventListener("change", function () {
      apply(sel.value);
      announce("Showing inputs for source: " + sel.value + ".");
    });
  })();

  // History: live auto-refresh.
  // Polls /history/latest.json every few seconds. When new requests are
  // recorded (matching the current filters), either reloads the page (if
  // the Auto-refresh checkbox is on) or shows a "N new — Refresh" link
  // (if the checkbox is off). Polling pauses while the tab is hidden.
  (function () {
    var root = document.querySelector("[data-history-live]");
    if (!root) return;
    var url = root.getAttribute("data-latest-url") || "/history/latest.json";
    var since = parseInt(root.getAttribute("data-since") || "0", 10) || 0;
    var cb = document.getElementById("hist-live-cb");
    var status = document.getElementById("hist-live-status");
    var POLL_MS = 2500;
    var RELOAD_DELAY_MS = 600;
    var timer = null;
    var reloadTimer = null;
    var stopped = false;
    // Tracks the last value spoken by the live region so we only
    // repaint (and therefore re-announce) on actual change. Sentinel
    // -1 means "nothing has been announced yet" so the first 0 from
    // the server still settles the UI without speaking.
    var lastAnnouncedCount = -1;

    var STORAGE_KEY = "reqloreHistoryAutoRefresh";
    try {
      // Default OFF (WCAG SC 3.2.5 Change on Request, AAA): the first
      // reload must be user-initiated. Users who flip the toggle ON have
      // their preference remembered across page loads.
      var saved = localStorage.getItem(STORAGE_KEY);
      if (saved === "on") cb.checked = true;
    } catch (_) { /* ignore */ }

    if (cb) {
      cb.addEventListener("change", function () {
        try {
          localStorage.setItem(STORAGE_KEY, cb.checked ? "on" : "off");
        } catch (_) { /* ignore */ }
        if (cb.checked && status && status.classList.contains("has-new")) {
          scheduleReload();
        } else if (!cb.checked && reloadTimer) {
          clearTimeout(reloadTimer);
          reloadTimer = null;
        }
      });
    }

    function userIsBusy() {
      // Don't yank the page out from under the user mid-interaction.
      // Skip the auto-reload if focus is in a form control or any
      // row-actions menu is open; the "N new — Refresh" link stays
      // visible so the user can reload on their own terms.
      var ae = document.activeElement;
      if (ae && /^(INPUT|TEXTAREA|SELECT)$/.test(ae.tagName)) return true;
      var openMenu = document.querySelector(
        '[data-row-actions] [aria-expanded="true"]'
      );
      return !!openMenu;
    }

    function scheduleReload() {
      if (reloadTimer) return;
      reloadTimer = setTimeout(function () {
        reloadTimer = null;
        if (userIsBusy()) {
          // Retry on the next poll tick; the visible Refresh link is
          // the user's escape hatch in the meantime.
          return;
        }
        // Preserve the user's current URL (filters, page, hash) AND
        // SR position on reload — after the new HTML lands, focus is
        // restored inside #hist-table so the screen reader resumes
        // reading the data, not from the top of the page.
        if (window.Reqlore && window.Reqlore.stashFocusTarget) {
          window.Reqlore.stashFocusTarget("#hist-table");
        }
        window.location.reload();
      }, RELOAD_DELAY_MS);
    }

    function paint(newCount) {
      if (!status) return;
      // SC 4.1.3 / 2.2.4: only update the live region when the count
      // actually CHANGES. Re-painting an unchanged value would cause
      // some screen readers to re-announce on every poll, which
      // hammers the user with a repeating chatter.
      if (newCount === lastAnnouncedCount) return;
      lastAnnouncedCount = newCount;

      // The Refresh link is a SIBLING of the role="status" element
      // (see template). The status text holds only the prose count;
      // the link's label never enters the live region, so AT speak
      // the count change cleanly.
      var refresh = document.getElementById("hist-live-refresh");
      if (newCount > 0) {
        var noun = newCount === 1 ? "request" : "requests";
        status.classList.add("has-new");
        status.textContent = newCount + " new " + noun + ".";
        if (refresh) {
          refresh.hidden = false;
          refresh.href = window.location.href;
          // Refresh-now click also stashes a focus target so the
          // screen reader lands inside #hist-table after navigation
          // instead of jumping back to <body>.
          if (!refresh._reqloreFocusWired) {
            refresh._reqloreFocusWired = true;
            refresh.addEventListener("click", function () {
              if (window.Reqlore && window.Reqlore.stashFocusTarget) {
                window.Reqlore.stashFocusTarget("#hist-table");
              }
            });
          }
        }
        if (cb && cb.checked) scheduleReload();
      } else {
        status.classList.remove("has-new");
        status.textContent = "";
        if (refresh) refresh.hidden = true;
      }
    }

    function poll() {
      if (stopped) return;
      if (document.hidden) { schedule(); return; }
      var sep = url.indexOf("?") >= 0 ? "&" : "?";
      var u = url + sep + "since=" + encodeURIComponent(since);
      fetch(u, { credentials: "same-origin", headers: { "Accept": "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (data && typeof data.new === "number") paint(data.new);
        })
        .catch(function () { /* network blips: silent, try again next tick */ })
        .then(function () { schedule(); });
    }

    function schedule() {
      if (stopped) return;
      timer = setTimeout(poll, POLL_MS);
    }

    document.addEventListener("visibilitychange", function () {
      if (!document.hidden) {
        // Resume immediately when the tab comes back into view.
        if (timer) { clearTimeout(timer); timer = null; }
        poll();
      }
    });

    schedule();
  })();

  // History per-column filter menus (the <details> dropdowns under
  // each filterable <th>). Native <details> already gives us toggle
  // behaviour and keyboard activation; this wires the bits the
  // browser doesn't:
  //   * Opening one column's menu closes any other open menu (so
  //     users don't end up with three overlapping panels).
  //   * On open the panel is upgraded to role="dialog"
  //     aria-modal="true" aria-labelledby="<summary id>" and the
  //     summary gets aria-haspopup="dialog" aria-expanded="true" —
  //     this is the same pattern as the row Actions menu's
  //     role="menu" upgrade and forces NVDA / JAWS / VoiceOver
  //     into focus mode, constraining their virtual cursor inside
  //     the panel. The role/attrs are stripped on close.
  //   * Escape inside an open menu closes it AND returns focus to
  //     its <summary> trigger (SC 2.4.3 Focus Order).
  //   * Clicking outside any menu closes them all.
  //   * On open, focus moves to the first input/checkbox/radio in
  //     the panel (SC 2.4.3 / 3.2.2).
  //   * Tab / Shift+Tab cycle inside the open panel — the menu
  //     behaves like a modal popup: keyboard + screen-reader users
  //     never accidentally walk past the menu into the next column
  //     header or row while the menu is open. Escape (or Cancel)
  //     is the only way out without committing.
  //   * ArrowDown / ArrowUp / Home / End rove between focusable
  //     panel items when the focused control doesn't already use
  //     arrows (so checkboxes + buttons get menu-style nav, while
  //     text inputs keep caret movement, number inputs keep
  //     increment/decrement, and radio groups keep native group nav).
  //     Left / Right are never intercepted.
  // Pressing Enter inside any field still submits the wrapping
  // <form id="hist-filters"> normally — that's how the filters
  // commit. Auto-submit on every checkbox change is intentionally
  // NOT done: SC 3.2.5 (Change on Request, AAA) requires the user
  // to explicitly trigger context changes.
  (function () {
    var menus = document.querySelectorAll('[data-hist-col-filter]');
    if (!menus.length) return;

    var FOCUSABLE = 'input:not([disabled]):not([type="hidden"]),' +
                    'select:not([disabled]),' +
                    'textarea:not([disabled]),' +
                    'button:not([disabled]),' +
                    'a[href],' +
                    '[tabindex]:not([tabindex="-1"])';

    function panelFocusables(d) {
      var panel = d.querySelector('.hist-col-filter-panel');
      if (!panel) return [];
      // Filter out elements that are visually hidden by CSS — open
      // panels paint everything, but be defensive in case a hidden
      // helper is ever added.
      return Array.prototype.filter.call(
        panel.querySelectorAll(FOCUSABLE),
        function (el) { return el.offsetParent !== null || el === document.activeElement; }
      );
    }

    function closeOthers(except) {
      menus.forEach(function (d) {
        if (d !== except && d.open) d.open = false;
      });
    }

    function closeMenu(d, restoreFocus) {
      if (!d.open) return;
      d.open = false;
      // upgradeForOpen() runs via the toggle handler when d.open
      // flips back to false, which restores role="group" and
      // strips dialog/modal/labelledby/tabindex. We don't have to
      // mirror that here.
      if (restoreFocus) {
        var summary = d.querySelector('summary');
        if (summary) summary.focus();
      }
    }

    // Upgrade the panel to a modal dialog on open / downgrade on
    // close. This is the equivalent of the row Actions menu's
    // role="menu" upgrade — both put screen readers into focus
    // mode so the virtual cursor stays inside the popup. We use
    // role="dialog" + aria-modal="true" (rather than role="menu")
    // because the popup contains form controls, not menuitems;
    // dialog is the APG-correct container for that. On close we
    // restore role="group" so the closed (still-rendered) markup
    // remains semantically correct for any AT that ignores
    // hidden/closed <details> bodies.
    function upgradeForOpen(d) {
      var panel = d.querySelector('.hist-col-filter-panel');
      var summary = d.querySelector('summary');
      if (!panel || !summary) return;
      panel.setAttribute('role', 'dialog');
      panel.setAttribute('aria-modal', 'true');
      panel.setAttribute('aria-labelledby', summary.id);
      panel.setAttribute('tabindex', '-1');
      summary.setAttribute('aria-haspopup', 'dialog');
      summary.setAttribute('aria-expanded', 'true');
    }
    function downgradeForClose(d) {
      var panel = d.querySelector('.hist-col-filter-panel');
      var summary = d.querySelector('summary');
      if (!panel || !summary) return;
      panel.setAttribute('role', 'group');
      panel.removeAttribute('aria-modal');
      panel.removeAttribute('aria-labelledby');
      panel.removeAttribute('tabindex');
      summary.setAttribute('aria-haspopup', 'dialog');
      summary.setAttribute('aria-expanded', 'false');
    }

    // Announce the haspopup contract on every summary up-front, so
    // SR users hear "<column> filter, collapsed, has popup, dialog"
    // even before they open one.
    menus.forEach(function (d) {
      var summary = d.querySelector('summary');
      if (summary) {
        summary.setAttribute('aria-haspopup', 'dialog');
        summary.setAttribute('aria-expanded', d.open ? 'true' : 'false');
      }
    });

    menus.forEach(function (d) {
      var summary = d.querySelector('summary');

      d.addEventListener('toggle', function () {
        if (d.open) {
          closeOthers(d);
          upgradeForOpen(d);
          var first = panelFocusables(d)[0];
          if (first) {
            // Defer until after the browser has painted the panel
            // so screen readers detect the focused control's new
            // visibility, not its hidden state.
            setTimeout(function () { first.focus(); }, 0);
          }
        } else {
          downgradeForClose(d);
        }
      });

      // Cancel button = close without committing, restore focus to
      // the summary trigger. The browser's default <button> inside
      // a <form> would submit the form; the click handler runs
      // first and we preventDefault to swallow the submit.
      var cancelBtn = d.querySelector('[data-hist-filter-close]');
      if (cancelBtn) {
        cancelBtn.addEventListener('click', function (ev) {
          ev.preventDefault();
          closeMenu(d, true);
        });
      }

      d.addEventListener('keydown', function (ev) {
        if (!d.open) return;

        // Escape: close + restore focus (SC 2.4.3 Focus Order).
        if (ev.key === 'Escape') {
          ev.preventDefault();
          closeMenu(d, true);
          return;
        }

        // Arrow / Home / End roving inside the panel. Native HTML
        // doesn't move focus between siblings on Up/Down, so by
        // default arrows wouldn't escape — but a checkbox-heavy
        // panel feels broken if arrows do nothing. We add APG
        // menu-style roving for the controls that DON'T already
        // own arrow behaviour, and we leave the rest alone:
        //
        //   * text-like inputs   -> caret movement (keep native)
        //   * number inputs      -> increment / decrement (keep)
        //   * <select>, <textarea> -> native value / caret (keep)
        //   * radio groups       -> native group navigation (keep)
        //   * checkboxes, buttons, links, [tabindex] -> roving
        //
        // ArrowLeft / ArrowRight are never intercepted: text caret
        // and radio-group navigation depend on them.
        //
        // Caveat: in NVDA/JAWS *browse* mode, arrow keys move the
        // virtual cursor and never reach this handler. We can't
        // trap browse-mode reading; the menu still survives because
        // committing requires Enter / Apply / Esc, all of which
        // work whatever mode the SR is in.
        if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp' ||
            ev.key === 'Home'       || ev.key === 'End') {
          var t = ev.target;
          var tag = (t && t.tagName ? t.tagName : '').toLowerCase();
          var typ = (t && t.type ? t.type : '').toLowerCase();
          var nativeArrows = (
            tag === 'select' || tag === 'textarea' ||
            (tag === 'input' && (
              typ === 'text' || typ === 'search' || typ === 'url' ||
              typ === 'email' || typ === 'password' || typ === 'tel' ||
              typ === 'number' || typ === 'date' || typ === 'datetime-local' ||
              typ === 'month' || typ === 'time' || typ === 'week' ||
              typ === 'radio'
            ))
          );
          if (!nativeArrows) {
            var ritems = panelFocusables(d);
            if (ritems.length) {
              var ridx = ritems.indexOf(document.activeElement);
              ev.preventDefault();
              if (ev.key === 'Home') ritems[0].focus();
              else if (ev.key === 'End') ritems[ritems.length - 1].focus();
              else if (ev.key === 'ArrowDown') {
                ritems[(ridx + 1 + ritems.length) % ritems.length].focus();
              } else if (ev.key === 'ArrowUp') {
                ritems[(ridx - 1 + ritems.length) % ritems.length].focus();
              }
              return;
            }
          }
          // Otherwise fall through and let the browser handle it.
        }

        // Tab trap. Cycle within panelFocusables; the <summary>
        // itself is INTENTIONALLY excluded from the cycle because
        // refocusing it would leak focus back onto the column
        // header and confuse the screen reader about whether the
        // menu is still in scope.
        if (ev.key !== 'Tab') return;
        var items = panelFocusables(d);
        if (items.length === 0) return;
        var first = items[0];
        var last = items[items.length - 1];
        var active = document.activeElement;
        // If focus has somehow already escaped the panel (e.g. user
        // clicked the summary while a control was focused), pull it
        // back to the appropriate edge.
        var inside = items.indexOf(active) !== -1;
        if (ev.shiftKey) {
          if (!inside || active === first) {
            ev.preventDefault();
            last.focus();
          }
        } else {
          if (!inside || active === last) {
            ev.preventDefault();
            first.focus();
          }
        }
      });
    });

    // Click outside any menu = close them all. Use mousedown so the
    // close happens BEFORE focus moves into the new click target,
    // which is what most native menu widgets do.
    document.addEventListener('mousedown', function (ev) {
      var any = false;
      menus.forEach(function (d) { if (d.open) any = true; });
      if (!any) return;
      // If the click originated inside ANY of our menus or their
      // toggles, leave it alone — the toggle handler will manage it.
      var t = ev.target;
      while (t && t.nodeType === 1) {
        if (t.matches && t.matches('[data-hist-col-filter]')) return;
        t = t.parentNode;
      }
      menus.forEach(function (d) { if (d.open) d.open = false; });
    });
  })();

  // --------------------------------------------------------------------
  // Live polling: Plugin app run page (plugins/app_run.html)
  //
  // Moved out of an inline <script> so the strict CSP
  // (script-src 'self', no 'unsafe-inline') doesn't block it.
  // The template emits a hidden <div data-plugin-run-poll …> with the
  // poll URL, column list and initial activity flag, plus a visible
  // <div class="run-live-controls"> with a checkbox to start/stop
  // auto-refresh and a "Refresh now" link. We honour the checkbox
  // (WCAG 2.2.2 Pause, Stop, Hide — Level A; aria-live region keeps
  // SR users informed of state changes at AAA quality).
  // --------------------------------------------------------------------
  (function () {
    var cfg = document.querySelector('[data-plugin-run-poll]');
    if (!cfg) return;
    var pollUrl = cfg.getAttribute('data-poll-url') || '';
    if (!pollUrl) return;
    var serverIsRunning = cfg.getAttribute('data-is-running') === 'true';
    var columns = [];
    try { columns = JSON.parse(cfg.getAttribute('data-columns') || '[]'); }
    catch (_) { columns = []; }

    var STORAGE_KEY = 'reqlorePluginRunAutoRefresh';
    var POLL_MS = 1000;

    var logEl = document.getElementById('run-log');
    var statusEl = document.getElementById('run-status');
    var finishedEl = document.getElementById('run-finished');
    var progEl = document.getElementById('run-progress');
    var progTextEl = document.getElementById('run-progress-text');
    var resTable = document.getElementById('run-results');
    var resBody = document.getElementById('run-results-body');
    var resCount = document.getElementById('run-results-count');

    var cb = document.getElementById('run-live-cb');
    var liveStatusEl = document.getElementById('run-live-status');
    var refreshLink = document.getElementById('run-live-refresh');

    // Load persisted preference; default = follow the server's
    // is_running flag (ON while a run is alive, OFF after it ends).
    var stored = null;
    try { stored = localStorage.getItem(STORAGE_KEY); } catch (_) { /* ignore */ }
    var enabled = (stored == null) ? serverIsRunning : (stored === 'on');
    if (cb) cb.checked = enabled;
    if (refreshLink) refreshLink.hidden = false;

    var runDone = !serverIsRunning;
    var pending = null;
    var inFlight = false;

    function announce(msg) {
      if (!liveStatusEl) return;
      // Clear first so SR re-reads even when the new text equals the old.
      liveStatusEl.textContent = '';
      setTimeout(function () { liveStatusEl.textContent = msg; }, 50);
    }
    function setBusy(b) { cfg.setAttribute('aria-busy', b ? 'true' : 'false'); }

    function renderRow(row) {
      var tr = document.createElement('tr');
      if (columns && columns.length) {
        columns.forEach(function (c) {
          var td = document.createElement('td');
          td.textContent = (row && row[c] != null) ? String(row[c]) : '';
          tr.appendChild(td);
        });
      } else {
        var td = document.createElement('td');
        var code = document.createElement('code');
        code.textContent = JSON.stringify(row);
        td.appendChild(code);
        tr.appendChild(td);
      }
      return tr;
    }

    function apply(data) {
      if (!data) return;
      if (data.log_tail && logEl) {
        logEl.appendChild(document.createTextNode(data.log_tail));
        logEl.setAttribute('data-log-offset', String(data.log_offset));
        logEl.scrollTop = logEl.scrollHeight;
      }
      if (data.new_results && data.new_results.length && resBody) {
        data.new_results.forEach(function (row) { resBody.appendChild(renderRow(row)); });
        if (resTable) resTable.setAttribute('data-results-offset', String(data.results_offset));
        if (resCount) resCount.textContent = String(data.results_offset);
      }
      if (statusEl) statusEl.textContent = data.status || '';
      if (progEl) {
        if (data.progress_total > 0) {
          progEl.value = data.progress_done;
          progEl.max = data.progress_total;
          progEl.setAttribute(
            'aria-valuetext',
            data.progress_done + ' of ' + data.progress_total
              + (data.progress_msg ? ': ' + data.progress_msg : '')
          );
        } else {
          progEl.removeAttribute('value');
          progEl.setAttribute(
            'aria-valuetext',
            (data.progress_done || 0) + ' step(s) completed'
              + (data.progress_msg ? ': ' + data.progress_msg : '')
          );
        }
      }
      if (progTextEl) {
        var parts = [];
        parts.push(String(data.progress_done || 0));
        if (data.progress_total) parts.push('/' + data.progress_total);
        if (data.progress_msg) parts.push(' \u2014 ' + data.progress_msg);
        progTextEl.textContent = parts.join('');
      }
      if (data.finished_at && finishedEl) {
        finishedEl.textContent = String(data.finished_at);
      }
      if (!data.is_running && !runDone) {
        runDone = true;
        if (cb) cb.disabled = true;
        announce('Run finished — auto-refresh stopped.');
      }
    }

    function doFetch(reason) {
      if (inFlight) return;
      inFlight = true;
      var logOffset = logEl ? parseInt(logEl.getAttribute('data-log-offset') || '0', 10) : 0;
      var resOffset = resTable ? parseInt(resTable.getAttribute('data-results-offset') || '0', 10) : 0;
      var url = pollUrl + (pollUrl.indexOf('?') >= 0 ? '&' : '?')
              + 'log_offset=' + logOffset + '&results_offset=' + resOffset;
      fetch(url, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(apply)
        .catch(function () { /* swallow; retry next tick */ })
        .finally(function () {
          inFlight = false;
          if (reason === 'manual') announce('Refreshed.');
          schedule();
        });
    }

    function schedule() {
      if (pending) { clearTimeout(pending); pending = null; }
      if (runDone || !cb || !cb.checked) { setBusy(false); return; }
      setBusy(true);
      pending = setTimeout(function () { pending = null; doFetch('auto'); }, POLL_MS);
    }

    if (cb) {
      cb.addEventListener('change', function () {
        try { localStorage.setItem(STORAGE_KEY, cb.checked ? 'on' : 'off'); }
        catch (_) { /* storage may be denied; preference becomes session-only */ }
        if (cb.checked) {
          if (runDone) {
            announce('Run finished — nothing to refresh.');
          } else {
            announce('Auto-refresh on.');
            schedule();
          }
        } else {
          announce('Auto-refresh off.');
          if (pending) { clearTimeout(pending); pending = null; }
          setBusy(false);
        }
      });
    }
    if (refreshLink) {
      refreshLink.addEventListener('click', function (ev) {
        ev.preventDefault();
        if (runDone) { announce('Run finished — nothing to refresh.'); return; }
        announce('Refreshing\u2026');
        if (pending) { clearTimeout(pending); pending = null; }
        doFetch('manual');
      });
    }

    if (enabled && !runDone) {
      setBusy(true);
      pending = setTimeout(function () { pending = null; doFetch('auto'); }, 500);
    } else if (runDone && cb) {
      cb.disabled = true;
    }
  })();

  // --------------------------------------------------------------------
  // Live polling: Auth-Matrix run detail (auth_matrix/runs_detail.html)
  //
  // Same UX as the plugin module: hidden config div + visible
  // <div class="run-live-controls"> with checkbox + "Refresh now"
  // link + aria-live status region. localStorage key is distinct so
  // the two surfaces don't share preferences.
  // --------------------------------------------------------------------
  (function () {
    var cfg = document.querySelector('[data-auth-matrix-run-poll]');
    if (!cfg) return;
    var pollUrl = cfg.getAttribute('data-poll-url') || '';
    if (!pollUrl) return;
    var serverIsRunning = cfg.getAttribute('data-is-running') === 'true';

    var STORAGE_KEY = 'reqloreAuthMatrixRunAutoRefresh';
    var POLL_MS = 1200;
    var RELOAD_DELAY_MS = 600;

    var statusEl = document.getElementById('run-status');
    var progEl = document.getElementById('run-progress');
    var progTextEl = document.getElementById('run-progress-text');
    var progMsgEl = document.getElementById('run-progress-msg');

    var cb = document.getElementById('run-live-cb');
    var liveStatusEl = document.getElementById('run-live-status');
    var refreshLink = document.getElementById('run-live-refresh');

    var stored = null;
    try { stored = localStorage.getItem(STORAGE_KEY); } catch (_) { /* ignore */ }
    var enabled = (stored == null) ? serverIsRunning : (stored === 'on');
    if (cb) cb.checked = enabled;
    if (refreshLink) refreshLink.hidden = false;

    var runDone = !serverIsRunning;
    var pending = null;
    var inFlight = false;

    function announce(msg) {
      if (!liveStatusEl) return;
      liveStatusEl.textContent = '';
      setTimeout(function () { liveStatusEl.textContent = msg; }, 50);
    }
    function setBusy(b) { cfg.setAttribute('aria-busy', b ? 'true' : 'false'); }

    function apply(data) {
      if (!data) return;
      if (statusEl) statusEl.textContent = data.status || '';
      if (progEl) {
        progEl.value = data.progress_done || 0;
        progEl.max = data.progress_total > 0 ? data.progress_total : 1;
        progEl.setAttribute(
          'aria-valuetext',
          (data.progress_done || 0) + ' of ' + (data.progress_total || 0)
            + (data.progress_msg ? ': ' + data.progress_msg : '')
        );
      }
      if (progTextEl) {
        progTextEl.textContent = (data.progress_done || 0) + ' / ' + (data.progress_total || 0);
      }
      if (progMsgEl) progMsgEl.textContent = data.progress_msg || '';
      if (data.verdict_counts) {
        Object.keys(data.verdict_counts).forEach(function (k) {
          var el = document.querySelector('[data-verdict-count="' + k + '"]');
          if (el) el.textContent = data.verdict_counts[k];
        });
      }
      if (!data.is_running && !runDone) {
        runDone = true;
        if (cb) cb.disabled = true;
        announce('Run finished — reloading to show new cells.');
        // Reload once so freshly-recorded cells render into the table.
        setTimeout(function () { window.location.reload(); }, RELOAD_DELAY_MS);
      }
    }

    function doFetch(reason) {
      if (inFlight) return;
      inFlight = true;
      fetch(pollUrl, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(apply)
        .catch(function () {})
        .finally(function () {
          inFlight = false;
          if (reason === 'manual') announce('Refreshed.');
          schedule();
        });
    }

    function schedule() {
      if (pending) { clearTimeout(pending); pending = null; }
      if (runDone || !cb || !cb.checked) { setBusy(false); return; }
      setBusy(true);
      pending = setTimeout(function () { pending = null; doFetch('auto'); }, POLL_MS);
    }

    if (cb) {
      cb.addEventListener('change', function () {
        try { localStorage.setItem(STORAGE_KEY, cb.checked ? 'on' : 'off'); }
        catch (_) { /* ignore */ }
        if (cb.checked) {
          if (runDone) {
            announce('Run finished — nothing to refresh.');
          } else {
            announce('Auto-refresh on.');
            schedule();
          }
        } else {
          announce('Auto-refresh off.');
          if (pending) { clearTimeout(pending); pending = null; }
          setBusy(false);
        }
      });
    }
    if (refreshLink) {
      refreshLink.addEventListener('click', function (ev) {
        ev.preventDefault();
        if (runDone) { announce('Run finished — nothing to refresh.'); return; }
        announce('Refreshing\u2026');
        if (pending) { clearTimeout(pending); pending = null; }
        doFetch('manual');
      });
    }

    if (enabled && !runDone) {
      setBusy(true);
      pending = setTimeout(function () { pending = null; doFetch('auto'); }, 600);
    } else if (runDone && cb) {
      cb.disabled = true;
    }
  })();
})();
