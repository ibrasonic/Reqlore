# Reqlore — Master Plan

**One-line:** Professional-grade web application pentesting suite, Python-native, accessible-first, local web UI.

**Status:** Phase 1 in progress. See `ROADMAP.md` for what's done.

---

## Why this exists

The industry-standard desktop pentest suites are Java/JavaFX desktop applications. Screen readers cope with them badly: focus traps in custom-painted tables, inaccessible tabs, no semantic structure, no keyboard-discoverable bindings.

Reqlore is built ground-up as a **server-rendered local web app**, where every screen is plain semantic HTML5 + Jinja2. That surface is the most reliable substrate for NVDA, JAWS, Orca, and VoiceOver. Equivalent professional functionality lives behind it, implemented in pure Python.

## Goals

1. **Functional parity with the free tier of the leading desktop suite, plus most of the paid tier** — see `FEATURES.md` for the matrix.
2. **WCAG 2.2 AA** measured continuously by axe-core, manually by NVDA/Orca/VoiceOver before each release.
3. **No dependency on curl** for runtime traffic. curl remains a *render target* for "Copy as curl" — every request the tool issues can be exported as a curl command for the book and for sharing.
4. **Powerful, not minimal.** Three HTTP engines (httpx, raw socket, optional curl-impersonate) cover everything the legacy desktop suites do plus a few things they don't (HTTP/3, JA3 spoofing).
5. **Reliable.** Unit + integration tests against the local vuln-bank / shop / social labs; CI gate on a11y + tests.
6. **Local-first, privacy-respecting.** Binds 127.0.0.1 only. No telemetry. No third-party calls without opt-in.

## Non-goals

- Cloud / SaaS deployment. Reqlore is a local tool.
- A native desktop GUI (Qt, GTK, etc.). The web UI is the GUI, in your default browser, where the OS accessibility stack already works.
- Replacing every third-party plugin / paid-tier feature in v1. Plugin API ships in Phase 3 so the community can extend.

## Audience

- Blind and low-vision pentesters who currently struggle with the existing desktop suites.
- Sighted pentesters who prefer keyboard-driven, scriptable, version-controllable tooling.
- Students working through the *Web Pentesting* book (this repo's sibling) who want a tool that maps 1:1 to the curl recipes they're learning.

## Single source of truth

| Document | What it answers |
|---|---|
| `PLAN.md` (this file) | Why and what at the top level |
| `ARCHITECTURE.md` | How the pieces fit together |
| `FEATURES.md` | Full module-by-module feature matrix |
| `ROADMAP.md` | Phase status, ordered task list |
| `ACCESSIBILITY.md` | WCAG checklist, SR test results, a11y patterns |
| `SECURITY.md` | Threat model of the tool itself |
| `PLUGINS.md` | Plugin API contract |
| `CONTRIBUTING.md` | How to add a feature, test, ship a release |
