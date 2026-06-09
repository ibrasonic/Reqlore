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
})();
