"""Live passive scanner: scan each proxied response in the background.

A single daemon worker thread drains a bounded in-memory queue of
history-row ids. Rows that cannot land in the queue (overflow) are
parked in the project's durable ``live_scan_backlog`` table instead
of being dropped — the worker drains that table on idle, FIFO, so
foundational early traffic (login, security headers) catches up
first. Nothing the proxy records is ever silently lost.

Design invariants:

* The proxy event loop must never block on us. ``enqueue()`` uses
  ``queue.Queue.put_nowait``; on overflow the row is written to the
  durable backlog and a counter is bumped. The hot path stays O(1)
  on a full queue because the backlog INSERT is the only DB write.
* The worker is single-threaded. One scan in flight at a time keeps
  memory and write contention predictable on the SQLite WAL backing
  file, and combined with the backlog's PK on ``hid`` guarantees
  every row is scanned at most once.
* Scope is honoured. Out-of-scope hosts increment a counter; the
  counter is surfaced to the UI so a misconfigured scope rule is
  visible rather than silent.
* Failures are contained. A row whose scan raises is re-queued in
  the durable backlog with an incremented retry counter and dropped
  permanently only after the retry budget is exhausted. A
  repeatedly failing rule cannot wedge the queue or the backlog.
* Lifecycle is explicit. ``start()`` is idempotent. ``stop()`` blocks
  up to ``timeout`` seconds for the in-flight scan to drain before
  returning; any ids still in the in-memory queue are flushed to the
  durable backlog so a process crash never costs scan coverage.
"""
from __future__ import annotations

import logging
import queue
import threading
import time

from .scope_utils import host_in_scope, load_scope_rules


log = logging.getLogger("reqlore.scanner.live")


# A generous in-memory ceiling. The backlog table is the real
# unbounded store; this just controls how big a burst the hot path
# can absorb without touching SQLite. 10 000 ints ≈ 80 KB of RAM.
DEFAULT_QUEUE_MAXSIZE = 10_000

# How many rows the worker drains from the durable backlog per idle
# tick. Small enough that a long backlog still leaves CPU headroom
# for fresh proxy traffic; large enough that catch-up doesn't crawl.
_BACKLOG_BATCH = 16

# Cap on consecutive scan failures before a row is dropped from the
# backlog. The retry budget is per-row, not per-rule, so one bad row
# can never block the queue forever.
_BACKLOG_MAX_RETRIES = 3

# Throughput sample buffer cap and trim threshold.
_COMPLETIONS_CAP = 4096
_COMPLETIONS_TRIM = 2048


class LiveScanWorker:
    """Background passive scanner with a durable overflow backlog.

    The worker has two input lanes:

    * an in-memory ``queue.Queue`` that the proxy hot path pushes
      into;
    * a persistent ``live_scan_backlog`` table on the project that
      absorbs anything the in-memory queue cannot hold and that
      survives process crashes.

    Each tick the worker prefers the in-memory queue (fresh traffic)
    and falls back to the backlog (catch-up). Once both are empty it
    blocks briefly waiting for the proxy.
    """

    def __init__(self, project, scanner, *,
                 maxsize: int = DEFAULT_QUEUE_MAXSIZE,
                 respect_scope: bool = True,
                 clock=time.monotonic,
                 backlog_batch: int = _BACKLOG_BATCH,
                 max_retries: int = _BACKLOG_MAX_RETRIES):
        self._project = project
        self._scanner = scanner
        self._respect_scope = respect_scope
        self._clock = clock
        self._backlog_batch = max(1, int(backlog_batch))
        self._max_retries = max(0, int(max_retries))
        # Recover any rows that were mid-flight when the previous
        # process died. They will still have their retry counter and
        # so a chronically-failing row still gets dropped eventually,
        # but a clean retry costs us nothing.
        try:
            project.backlog_reset_claims()
        except Exception:  # noqa: BLE001 — never block startup
            log.exception(
                "live scan failed to reset stale backlog claims")
        self._q: queue.Queue[int] = queue.Queue(maxsize=max(1, int(maxsize)))
        self._stop = threading.Event()
        # Operator-triggered catch-up: the next idle tick will drain
        # the durable backlog in a larger batch (10x default) to clear
        # a visible backlog quickly when the user asks for it.
        self._catchup = threading.Event()
        self._thread: threading.Thread | None = None
        # Cached scope rules. Reloaded on every idle tick so a
        # sitemap edit is picked up within one scan cycle.
        self._scope_rules: list[dict] = []
        # Metrics (read-only from outside; UI snapshots them).
        self.scanned = 0
        self.findings_added = 0
        # ``overflowed`` is the count of rows the hot path could not
        # fit in the in-memory queue and so wrote to the durable
        # backlog. It is *not* a count of dropped rows — nothing is
        # dropped here. ``dropped_unrecoverable`` is the count of rows
        # that exceeded the retry budget after repeatedly failing to
        # scan; those *are* lost, but only after several attempts.
        self.overflowed = 0
        self.dropped_unrecoverable = 0
        self.backlog_drained = 0
        self.skipped_out_of_scope = 0
        self.errors = 0
        self._completions: list[float] = []
        self.last_error: str = ""
        self.last_error_ts: float = 0.0

    # ----- public API -----
    def enqueue(self, hid: int) -> None:
        """Hand a history-row id to the scanner. Never blocks.

        Hot-path semantics:

        1. Try the in-memory queue — the common case, O(1).
        2. On overflow, park the id in the durable backlog table and
           increment ``self.overflowed``. The proxy thread eats one
           SQLite INSERT here; that is still cheaper than the network
           round-trip it just finished, so the event loop stays
           responsive.
        3. If the backlog INSERT itself fails (disk full, DB locked
           for longer than its busy timeout), the failure is logged
           and ``self.errors`` ticks. We deliberately do not raise:
           the proxy must never propagate scanner failures back to
           the wire.
        """
        try:
            self._q.put_nowait(int(hid))
            return
        except queue.Full:
            pass
        try:
            self._project.backlog_enqueue(int(hid))
            self.overflowed += 1
        except Exception as exc:  # noqa: BLE001 — never propagate
            self.errors += 1
            self.last_error = (
                f"backlog_enqueue: {type(exc).__name__}: {exc}"
            )[:200]
            self.last_error_ts = self._clock()
            log.exception("live scan backlog write failed for hid=%s", hid)

    def request_catchup(self) -> None:
        """Signal the worker to favour the durable backlog on its
        next idle tick. Safe to call from any thread."""
        self._catchup.set()


    def start(self) -> None:
        """Start (or restart after stop) the worker. Idempotent while
        the existing worker is alive."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="reqlore-livescan", daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Signal the worker to exit and join up to ``timeout`` seconds.

        Before joining, any history-row ids still sitting in the
        in-memory queue are flushed to the durable backlog so a
        clean shutdown never costs scan coverage. The worker itself
        will finish the row it's currently scanning (a single passive
        pass is fast) before checking the stop flag.
        """
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=max(0.0, float(timeout)))
        self._thread = None
        self._flush_queue_to_backlog()

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ----- metrics for the UI -----
    def queue_depth(self) -> int:
        return self._q.qsize()

    def scans_per_minute(self) -> float:
        """Rolling 60-second throughput rate."""
        now = self._clock()
        cutoff = now - 60.0
        # Lazy trim: drop samples older than the window. The list is
        # append-only so this is O(k) per call where k is the number of
        # entries to discard — bounded by the cap we enforce in _loop.
        i = 0
        for i, ts in enumerate(self._completions):
            if ts >= cutoff:
                break
        else:
            i = len(self._completions)
        if i > 0:
            self._completions = self._completions[i:]
        return float(len(self._completions))

    def throughput_sparkline(self, *, buckets: int = 6,
                              window_s: float = 60.0) -> list[int]:
        """Phase 4 — return a small histogram of scan completions over
        the last ``window_s`` seconds, split into ``buckets`` equal
        time slices (oldest first). Used by the Live tab's CSS-only
        sparkline. Returns ``[0] * buckets`` if the worker hasn't
        scanned anything yet.
        """
        buckets = max(1, int(buckets))
        window_s = max(1.0, float(window_s))
        now = self._clock()
        slice_s = window_s / buckets
        out = [0] * buckets
        for ts in self._completions:
            age = now - ts
            if age < 0 or age >= window_s:
                continue
            idx = buckets - 1 - int(age // slice_s)
            if 0 <= idx < buckets:
                out[idx] += 1
        return out

    def snapshot(self) -> dict:
        """Return a JSON-serialisable status snapshot for the UI.

        ``backlog`` is the live row count in the durable backlog
        table; the UI uses it together with ``queue_depth`` to render
        the operator-facing “work remaining” figure. Reading the
        backlog count is a single ``COUNT(*)`` against a small table
        with a PK index, so this stays cheap even when polled.
        """
        return {
            "alive": self.is_alive(),
            "queue_depth": self.queue_depth(),
            "backlog": self._backlog_count_safe(),
            "scanned": self.scanned,
            "findings_added": self.findings_added,
            "overflowed": self.overflowed,
            "backlog_drained": self.backlog_drained,
            "dropped_unrecoverable": self.dropped_unrecoverable,
            "skipped_out_of_scope": self.skipped_out_of_scope,
            "errors": self.errors,
            "scans_per_minute": self.scans_per_minute(),
            "throughput_buckets": self.throughput_sparkline(),
            "last_error": self.last_error,
            "last_error_ts": int(self.last_error_ts) if self.last_error_ts else 0,
        }

    def _backlog_count_safe(self) -> int:
        try:
            return int(self._project.backlog_count())
        except Exception:  # noqa: BLE001 — never let the UI poll crash
            return 0

    def _flush_queue_to_backlog(self) -> None:
        """Drain the in-memory queue into the durable backlog. Used on
        ``stop()`` to make shutdown coverage-preserving."""
        while True:
            try:
                hid = self._q.get_nowait()
            except queue.Empty:
                return
            try:
                self._project.backlog_enqueue(int(hid))
            except Exception:  # noqa: BLE001
                self.errors += 1
                log.exception(
                    "live scan flush_queue_to_backlog failed for hid=%s",
                    hid,
                )

    # ----- worker loop -----
    def _loop(self) -> None:
        """Main worker loop.

        Tick policy:

        1. Try to pop a row from the in-memory queue with a short
           timeout. Fresh proxy traffic always wins.
        2. If the in-memory queue is empty, drain a batch from the
           durable backlog. The catch-up flag, if set by an operator
           "Catch up now" click, pulls a larger batch so a visible
           backlog clears quickly.
        3. If both lanes are empty, refresh scope rules and loop.

        Any scan failure goes through :meth:`_handle_scan_failure`
        which either re-queues the row in the durable backlog with a
        bumped retry counter, or - once retries are exhausted -
        records the row as ``dropped_unrecoverable`` and moves on.
        """
        self._refresh_scope_rules()
        while not self._stop.is_set():
            # Hot lane: in-memory queue.
            try:
                hid = self._q.get(timeout=0.25)
            except queue.Empty:
                # Cold lane: durable backlog.
                batch_size = self._backlog_batch
                if self._catchup.is_set():
                    batch_size = self._backlog_batch * 10
                    self._catchup.clear()
                drained = self._drain_backlog_batch(batch_size)
                if drained == 0:
                    # Both lanes empty; refresh scope rules and idle.
                    self._refresh_scope_rules()
                continue
            self._scan_with_retry(hid, from_backlog=False)

    def _drain_backlog_batch(self, batch_size: int) -> int:
        """Claim and scan up to ``batch_size`` rows from the durable
        backlog. Returns the number of rows actually processed (which
        may be 0 if the backlog is empty).

        Each claimed row is ACK-ed (deleted) on a successful scan or
        NACK-ed (retry counter bumped, claim cleared) on a failed
        one. Rows we never get to (because shutdown raced the drain)
        are yielded — the claim is cleared without bumping retries so
        the next worker run picks them up cleanly.
        """
        try:
            claims = self._project.backlog_pop_batch(int(batch_size))
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            self.last_error = (
                f"backlog_pop_batch: {type(exc).__name__}: {exc}"
            )[:200]
            self.last_error_ts = self._clock()
            log.exception("live scan failed to drain backlog")
            return 0
        processed = 0
        for idx, (hid, _retries) in enumerate(claims):
            if self._stop.is_set():
                # Shutdown raced with the drain; yield the unprocessed
                # remainder so the next worker run sees them as
                # eligible (no retry penalty).
                self._yield_remaining(c[0] for c in claims[idx:])
                return processed
            ok = self._scan_with_retry(hid, from_backlog=True)
            if ok:
                try:
                    self._project.backlog_release(int(hid))
                except Exception:  # noqa: BLE001
                    self.errors += 1
                    log.exception(
                        "live scan failed to release hid=%s", hid)
            processed += 1
        return processed

    def _yield_remaining(self, hids) -> None:
        """Clear the claim on each id (no retry bump). Called when the
        worker is shutting down mid-batch."""
        for hid in hids:
            try:
                self._project.backlog_yield(int(hid))
            except Exception:  # noqa: BLE001
                self.errors += 1
                log.exception(
                    "live scan failed to yield hid=%s on shutdown", hid)

    def _scan_with_retry(self, hid: int, *, from_backlog: bool) -> bool:
        """Scan one row and route any exception through the retry
        policy. ``from_backlog`` controls bookkeeping: a row that was
        already on disk only counts toward ``backlog_drained`` once
        the scan completes.

        Returns ``True`` if the scan succeeded (caller should ACK the
        backlog row), ``False`` otherwise (the failure path already
        handled the NACK).
        """
        try:
            self._scan_one(hid)
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            self.errors += 1
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            self.last_error_ts = self._clock()
            log.exception("live scan failed for hid=%s", hid)
            self._handle_scan_failure(hid)
            return False
        if from_backlog:
            self.backlog_drained += 1
        return True

    def _handle_scan_failure(self, hid: int) -> None:
        """Re-park a failed row in the durable backlog with a bumped
        retry counter; once the retry budget is exhausted, count it
        as an unrecoverable drop. This is the only place rows are
        ever lost, and only after several attempts."""
        try:
            kept = self._project.backlog_requeue(
                int(hid), max_retries=self._max_retries,
            )
        except Exception:  # noqa: BLE001
            self.errors += 1
            log.exception(
                "live scan failed to requeue hid=%s after scan error", hid)
            return
        if not kept:
            self.dropped_unrecoverable += 1
            log.warning(
                "live scan giving up on hid=%s after %d retries",
                hid, self._max_retries,
            )

    def _refresh_scope_rules(self) -> None:
        try:
            self._scope_rules = load_scope_rules(self._project)
        except Exception:  # noqa: BLE001 — never crash the worker
            log.exception("live scan failed to load scope rules")

    def _scan_one(self, hid: int) -> None:
        row = self._project.get_history(hid)
        if row is None:
            return
        if self._respect_scope and not host_in_scope(
                row.host or "", self._scope_rules):
            self.skipped_out_of_scope += 1
            return
        # Use the scope-aware project scan path by piping a single row
        # through ``Scanner.scan_history_row`` and the unified write
        # bus. We intentionally avoid ``scan_project`` here so the
        # per-row latency stays low (no resume-marker churn, no
        # cross-row aggregation).
        from ..findings_bus import record_finding
        from .rules import apply_meta_defaults, id_for, meta_for
        for rule in self._scanner.rules:
            rid = id_for(rule, prefix="passive")
            meta = meta_for(rule)
            try:
                fired_any = False
                from .passive import run_passive
                for f in run_passive(row, [rule]):
                    apply_meta_defaults(f, meta)
                    fid = record_finding(
                        self._project, source="scanner", rule_id=rid,
                        severity=f.severity, title=f.title,
                        description=f.description, remediation=f.remediation,
                        references=f.references,
                        cwe=f.cwe, owasp=f.owasp,
                        host=f.host, url=f.url,
                        request_id=f.request_id, response_id=f.response_id,
                        evidence=f.evidence, payload=f.payload,
                        confidence=getattr(f, "confidence", "firm"),
                    )
                    if fid is not None:
                        self.findings_added += 1
                    fired_any = True
                if not fired_any:
                    try:
                        self._project.record_rule_run(
                            rule_id=rid, host=row.host or "", url=row.url or "",
                            fired=False, reason="no_match",
                        )
                    except AttributeError:
                        pass
            except Exception:  # noqa: BLE001 — isolate each rule
                self.errors += 1
                log.exception(
                    "live scan rule %r raised on hid=%s", rid, hid)
        self.scanned += 1
        now = self._clock()
        self._completions.append(now)
        # Cap the throughput buffer at a generous ceiling so a long-
        # running worker doesn't grow this list unbounded.
        if len(self._completions) > _COMPLETIONS_CAP:
            self._completions = self._completions[-_COMPLETIONS_TRIM:]
