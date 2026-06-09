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
          return;
        }
        if (a === hid) {
          ev.preventDefault();
          sessionStorage.removeItem(KEY);
          relabel();
          announce("Cleared compare A.");
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
