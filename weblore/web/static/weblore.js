/* Weblore — progressive enhancement only.
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
  window.Weblore = { announce: announce };

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
})();
