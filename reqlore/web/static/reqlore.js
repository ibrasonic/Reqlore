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

  // After form submit, move focus to <main> so SR users land somewhere predictable.
  document.querySelectorAll("form").forEach(function (f) {
    f.addEventListener("submit", function () {
      var m = document.getElementById("main");
      if (m) requestAnimationFrame(function () { m.focus(); });
    });
  });

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
  window.Reqlore = { announce: announce };

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
  // No JS: button stays [hidden]; the <ul> renders as a flat list of links.
  // With JS: button is shown, list is hidden until activated. We add
  // role=menu / menuitem, roving focus with arrow keys, Home/End, Esc,
  // a Tab focus-trap, click-outside-to-close, and 500ms type-ahead.
  (function () {
    var widgets = document.querySelectorAll("[data-row-actions]");
    if (!widgets.length) return;
    var openWidget = null;

    function items(w) {
      return Array.prototype.slice.call(
        w.querySelectorAll('a[role="menuitem"]'));
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
      list.querySelectorAll("li > a").forEach(function (a) {
        a.setAttribute("role", "menuitem");
        a.setAttribute("tabindex", "-1");
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
        // Preserve the user's current URL (filters, page, hash) on reload.
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
  //   * Escape inside an open menu closes it AND returns focus to
  //     its <summary> trigger (SC 2.4.3 Focus Order).
  //   * Clicking outside any menu closes them all.
  //   * On open, focus moves to the first input/checkbox/radio in
  //     the panel (SC 2.4.3 / 3.2.2).
  //   * Tab / Shift+Tab cycle inside the open panel — the menu
  //     behaves like a popup: keyboard + screen-reader users never
  //     accidentally walk past the menu into the next column header
  //     or row while the menu is open. Escape (or Cancel) is the
  //     only way out without committing.
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
      if (restoreFocus) {
        var summary = d.querySelector('summary');
        if (summary) summary.focus();
      }
    }

    menus.forEach(function (d) {
      var summary = d.querySelector('summary');

      d.addEventListener('toggle', function () {
        if (d.open) {
          closeOthers(d);
          var first = panelFocusables(d)[0];
          if (first) {
            // Defer until after the browser has painted the panel
            // so screen readers detect the focused control's new
            // visibility, not its hidden state.
            setTimeout(function () { first.focus(); }, 0);
          }
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
})();
