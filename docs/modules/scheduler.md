# Scheduler — `/schedule/`

Run [Scanner](scanner.md) passive scans on a fixed interval. Jobs
persist into `project_state` so they survive restarts. Backed by
APScheduler when the `[schedule]` extra is installed, otherwise a
simple 1-second polling thread.

## Where it is

- **URL:** `/schedule/`
- **Nav:** *Scheduler* in the top bar.
- Per-project — jobs persist across restarts.

## Quick start

1. Open `/schedule/`. Click **Start scheduler**.
2. Fill in **Name** (e.g. `nightly`), **Interval seconds** (e.g.
   `3600`), **Scan limit** (e.g. `5000`). Click **Add**.
3. The job appears in the table. Click **Run now** to fire it once
   immediately. Otherwise it ticks on the interval.
4. Status panel shows backend (`apscheduler` or `thread`) and running
   state.

## Routes

| URL                          | Method | What it does                                                                |
|------------------------------|--------|-----------------------------------------------------------------------------|
| `/schedule/`                 | GET    | Render status + job list + add form.                                         |
| `/schedule/start`            | POST   | Start the scheduler (APScheduler if installed, else thread fallback).        |
| `/schedule/stop`             | POST   | Stop the scheduler. Jobs persist but won't tick.                            |
| `/schedule/add`              | POST   | Add a job from form fields.                                                  |
| `/schedule/remove/<name>`    | POST   | Remove a job by name.                                                        |
| `/schedule/run/<name>`       | POST   | Run a single job immediately (synchronous; blocks until done).               |

## Form fields (add job)

| Field         | Type   | Default  | Notes                                                          |
|---------------|--------|----------|----------------------------------------------------------------|
| `name`        | text   | empty    | **Required.** Identifier; must be unique.                       |
| `interval_s`  | number | `3600`   | Seconds between runs. Min `30` (enforced).                      |
| `scan_limit`  | number | `1000`   | Max findings per run. Range 1 – 50,000.                         |

## Backends

- **APScheduler** (`pip install reqlore[schedule]`) — daemon-mode
  background scheduler. Recommended for production runs.
- **Thread fallback** — sleeps 1 s, polls a `next_run` dict, re-arms on
  each tick. Works without extra installs. Less precise but adequate
  for hourly cadence.

The backend is auto-selected; the UI status panel shows which is active.

## Multi-process safety

Only one Reqlore process at a time may run the scheduler against a given
project file. The lock is a JSON stamp persisted at
`project_state["sched:lock"]` shaped as
`{"pid": <int>, "host": <str>, "ts": <unix_int>}`.

Acquisition (on `Scheduler.start()`):

- A foreign stamp younger than **30 s** (the TTL) refuses the start with
  `SchedulerLockError`. The `/schedule/start` route catches the error
  and flashes the holder's pid + host so you know which process to
  stop.
- A stamp older than the TTL (likely a crashed process that never
  cleaned up) is silently overridden.
- A corrupt or unparseable stamp is silently overridden.
- A stamp owned by the current process is silently refreshed (so
  stop → start cycles inside a single Reqlore run always succeed).

Refresh: while the thread-fallback loop is running, the stamp is
re-written every **10 s** to keep the lease fresh.

Release (on `Scheduler.stop()`): the stamp row is cleared **only** if
it still belongs to this process. A foreign holder that grabbed the
slot after our TTL expired is never clobbered.

Boot behaviour: when `sched:auto_start` is on but the lock is held by
another process at app boot, the boot hook in
`reqlore/web/__init__.py` swallows the error — the app starts
normally, the scheduler simply stays stopped. Visit `/schedule/` and
click **Start scheduler** once the other process releases the lock
(or wait ≈ 30 s for the TTL to expire).

## Job schema

```json
{
  "name": "nightly",
  "interval_s": 3600,
  "scan_limit": 5000,
  "enabled": true,
  "last_run_ts": 1730000000,
  "last_findings": 23
}
```

Persisted as a JSON list under `project_state["sched:jobs"]`.

## Job execution

`Scheduler._run_job(name)`:

- Calls `Scanner(rules=BUILTIN_RULES).scan_project(limit=scan_limit)`.
- Updates `last_run_ts` (epoch seconds) and `last_findings` (count).
- Exceptions are caught and silently swallowed; the job re-arms for the
  next tick.

**Passive scans only** — no active checks, no custom rules, no
intruder. If you need active coverage on a schedule, wire it up
yourself via a plugin (see [Plugins](plugins.md)).

## Accessibility notes

- All form fields have `<label for="…">`.
- Job table: `<caption>Scheduled jobs</caption>` + `<th scope="col">`.
- Action buttons (`Run now`, `Remove`) are in per-row `<form>`s with
  CSRF tokens.
- No live updates — refresh the page to see new `last_run_ts`.

## How it integrates

**Producer:** none — scheduler is author-created.

**Consumer:** writes findings into the project via
`Scanner.scan_project()`. Surfaces in [Scanner](scanner.md) and
[Reporter](reporter.md).

## Recipes

### Hourly passive sweep of recorded history

Start scheduler → Add `name=hourly, interval_s=3600, scan_limit=5000`.
Every hour, all built-in passive rules run across the latest history
rows.

### Quick smoke

Add a job with `interval_s=30, scan_limit=100`. Click **Run now**
once; then leave it ticking for an hour to watch the per-run findings
count drift.

### Persistence test (from a Python shell)

```python
from reqlore.scheduler import Scheduler
s1 = Scheduler(project)
s1.add_job(name="x", interval_s=60, scan_limit=100)
s1.stop()
# Restart process
s2 = Scheduler(project)
assert [j.name for j in s2.list_jobs()] == ["x"]
```

### Remove a job

POST `/schedule/remove/<name>` (the table row's **Remove** button).
Jobs vanish from `project_state` immediately.

### Pre-flight before a long scan

Add a `name=smoke` job, **Run now**, inspect findings, then **Remove**.
Doesn't pollute long-term jobs.

## Storage footprint

- `project_state["sched:jobs"]` — JSON list of jobs.
- `project_state["sched:auto_start"]` — `"0"` / `"1"` flag; when on,
  the web boot hook starts the scheduler automatically.
- `project_state["sched:lock"]` — JSON stamp
  `{pid, host, ts}` for cross-process serialisation. Written on
  `start()`, refreshed every 10 s while running, cleared on `stop()`
  (only if still owned by this process). Stale stamps (older than
  30 s) are overridden on the next `start()` attempt.

No DB tables of its own; findings go into the `issues` table via
Scanner.

## CLI

No CLI surface. Scheduler lifetime is tied to the Reqlore process.
For a true cron-style integration, run `reqlore` under a process
supervisor and let it manage the scheduler.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| "interval_s must be >= 30" error                          | Sub-30s intervals rejected                                              | Bump to ≥ 30 s.                                                                                  |
| Jobs don't run after restart                              | Scheduler is stopped by default                                         | Click **Start scheduler** after each restart, or auto-start via a plugin.                        |
| Exception in scan silently lost                           | `_thread_loop()` catches and ignores                                    | Tail Reqlore stderr; if a rule's misbehaving, run it via `/scanner/` to surface the traceback.    |
| Two Reqlore processes corrupt `sched:jobs`                | Pre-Phase-18 — no longer possible                                       | The scheduler now holds a cross-process lock at `project_state["sched:lock"]`; the second process refuses to start. See **Multi-process safety** above.  |
| Start refused: "Scheduler is already running for this project (pid X on host Y)" | Another Reqlore process holds the lock                                  | Stop the other process, or wait ≈ 30 s for its TTL to expire. If you know that process crashed, just retry — the stale stamp is overridden automatically. |
| `last_run_ts` not updating                                 | Job is disabled                                                         | Disable / enable via Python API; the UI does not expose the flag.                                |
| Thread backend feels imprecise                            | 1-second poll resolution                                                | Install `reqlore[schedule]` for APScheduler.                                                     |

## Test contract

`reqlore/tests/unit/test_phase7.py`:

- `test_scheduler_add_remove_persists` — add → restart → still there; remove → gone.
- `test_scheduler_rejects_tiny_interval` — `interval_s=5` raises `ValueError`.
- `test_scheduler_run_now_invokes_scanner` — `run_now()` calls scanner, updates `last_run_ts` and `last_findings`.
- `test_scheduler_serialise_round_trip` — JSON round-trip preserves all fields.
