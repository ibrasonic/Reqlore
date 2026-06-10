# Reporter — `/reporter/`

The Reporter turns triaged [Scanner](scanner.md) findings into a
deliverable artefact — Markdown, self-contained HTML, DOCX, machine-readable
JSON, or SARIF 2.1.0 for the GitHub Security tab. Filterable by severity,
status, and optional classification banner; optional coverage section.

## Where it is

- **URL:** `/reporter/`
- **Nav:** *Reporter* in the top bar.
- Sub-paths are export endpoints, not pages: `/reporter/export.<fmt>` where
  `fmt ∈ {md, html, docx, json, sarif}`.

## Quick start

1. Triage your findings first — open [Scanner](scanner.md), set statuses to `triaged`, `false_positive`, `fixed`.
2. Open `/reporter/`. Pick the filters you want (e.g. *Severity: high*, *Status: open*).
3. Optional: type a *Classification* (e.g. `CONFIDENTIAL — ACME CORP`). Tick *Include coverage*.
4. Click one of **Markdown**, **HTML**, **DOCX**, **JSON**, **SARIF** — your browser downloads the file.

## Routes

| URL                          | Method | What it does                                                                            |
|------------------------------|--------|-----------------------------------------------------------------------------------------|
| `/reporter/`                 | GET    | Filter form, severity summary table, links to each export format.                        |
| `/reporter/export.md`        | GET    | Markdown report.                                                                         |
| `/reporter/export.html`      | GET    | Self-contained HTML (inlined CSS, no JS, no external assets).                            |
| `/reporter/export.docx`      | GET    | Microsoft Word DOCX. Requires `python-docx`; 400 if missing.                              |
| `/reporter/export.json`      | GET    | Versioned JSON (`schema: reqlore.findings/1`).                                            |
| `/reporter/export.sarif`     | GET    | SARIF 2.1.0 (`application/sarif+json`).                                                   |
| `/reporter/export.<other>`   | GET    | 404.                                                                                     |

## Filter form

| Field            | Type     | Default | Notes                                                                                  |
|------------------|----------|---------|----------------------------------------------------------------------------------------|
| `severity`       | select   | empty   | `critical`, `high`, `medium`, `low`, `info`, or any.                                   |
| `status`         | select   | empty   | `open`, `triaged`, `false_positive`, `fixed`, or any.                                  |
| `classification` | text     | empty   | Free-form banner string. Renderers may uppercase it.                                   |
| `coverage`       | checkbox | off     | Include rule-coverage section (rule totals + per-host breakdown).                       |

All filters round-trip via querystring: e.g.
`/reporter/export.md?severity=high&status=open&classification=Q4-2025&coverage=1`.

> **Single-value filters.** `severity` and `status` are single-pick. For
> "high + critical" you generate two reports.

## Format matrix

| Aspect                     | Markdown                  | HTML                              | DOCX                                | JSON                                | SARIF                              |
|----------------------------|---------------------------|-----------------------------------|-------------------------------------|-------------------------------------|------------------------------------|
| Renderer                   | `reporter/markdown.py`    | `reporter/html.py`                | `reporter/docx.py`                  | `reporter/json_export.py`           | `reporter/sarif.py`                |
| External dep               | none                      | none                              | `python-docx`                       | none                                | none                               |
| Evidence clip              | 800 chars                 | 1000 chars                        | 1500 chars                          | full                                | full                               |
| Payload clip               | 400 chars                 | 400 chars                         | 500 chars                           | full                                | full                               |
| Self-contained?            | n/a                       | yes — inlined CSS, zero JS, no external links | n/a                       | n/a                                 | n/a                                |
| Severity colour            | text-only (e.g. `[CRITICAL]`) | RGB badges (≥ 7:1 contrast)   | RGB headings (`A51A1A`, `C93B00`, …) | numeric severity field             | mapped: critical/high → `error`, medium/low → `warning`, info → `note` |
| Classification             | quote-style banner         | top banner                        | bold paragraph                      | top-level `classification` key       | not surfaced                       |
| Coverage section           | when `coverage=1`         | when `coverage=1`                 | when `coverage=1`                   | when `coverage=1` (separate keys)   | not surfaced                       |
| curl reproducer            | from `reproduction_token`  | same                              | same                                | reproduction_token field             | not surfaced                       |

## Finding fields in the report

All formats include: title, `rule_id`, source (`scanner` / `manual`),
CWE, OWASP, host, URL, CVSS score + vector (if present), status,
description, evidence (clipped), payload (clipped), curl reproducer (if
`reproduction_token` set), remediation, references.

JSON additionally exposes: id, uuid, rule_version, created_at,
updated_at.

## SARIF mapping

| SARIF field      | Source                                                              |
|------------------|---------------------------------------------------------------------|
| `tool.driver.name` | `"reqlore"`                                                        |
| `tool.driver.version` | current package version                                         |
| `tool.driver.rules[]` | unique `rule_id`s; `:` in id → `_` in SARIF rule id           |
| `results[].ruleId` | finding's `rule_id`                                                |
| `results[].level`  | critical/high → `error`, medium/low → `warning`, info → `note`     |
| `results[].locations[]` | derived from URL when present                                  |

## How it integrates

**Producers (data sources):**

- [Scanner](scanner.md) — every finding (passive and active) lands in
  the `issues` table; this is the report's primary input.
- `rule_runs` table — populates the optional coverage section.
- `finding_reproductions` — referenced by `reproduction_token` to
  synthesise the curl one-liner.

**Consumers (where reports go):**

- Browser download — `Content-Disposition: attachment`.
- SIEM / ticketing — pipe the JSON file in.
- GitHub Security tab — upload the SARIF file via `github/codeql-action/upload-sarif` or the API.

## Recipes

### Client-ready HTML with classification

```
GET /reporter/export.html?status=open&classification=CONFIDENTIAL%20%E2%80%94%20ACME
```

Self-contained, email-safe, printable.

### High-severity DOCX with coverage

```
GET /reporter/export.docx?severity=high&coverage=1
```

(Repeat for `severity=critical` to combine.)

### JSON for CI/CD gate

```
GET /reporter/export.json?status=open
```

Then in your pipeline:

```
jq '[.findings[] | select(.severity == "critical" or .severity == "high")] | length' findings.json
```

Fail the build if non-zero.

### SARIF for GitHub Security

```
curl -sSf http://127.0.0.1:8787/reporter/export.sarif -o findings.sarif
# In CI:
gh api -X POST repos/$REPO/code-scanning/sarifs \
  -f commit_sha="$GITHUB_SHA" -f ref="$GITHUB_REF" \
  -f sarif="$(gzip -c findings.sarif | base64 -w0)"
```

### Markdown for an internal wiki

```
GET /reporter/export.md?status=open
```

Paste straight into Confluence / GitHub wiki / Notion.

## Accessibility notes

### Report itself

- **Markdown:** plaintext semantic structure; severity labels in
  brackets (`[CRITICAL]`) for screen-reader skim.
- **HTML:**
  - `<a class="skip-link" href="#findings">Skip to findings</a>`.
  - Light/dark theming via `@media (prefers-color-scheme)`; severity
    badges hand-tuned to ≥ 7:1 contrast (WCAG AAA).
  - `<table><caption>` + `<th scope="col">` / `<th scope="row">` for
    summary and coverage tables.
  - Each finding is `<article class="finding" aria-labelledby="f-<id>">`
    with `<h3 id="f-<id>">`.
  - Metadata rendered as `<dl>` with `<dt>` / `<dd>` pairs.
- **DOCX:** heading hierarchy (H1 / H2 / H3) for outline navigation;
  "Light Grid" tables for visible borders.
- **JSON / SARIF:** machine-readable, no accessibility surface.

### Reporter form page

- Standard `<label for="…">` on every input.
- Server-side filtering only; full reload on submit (no live update).

## Storage footprint

**Reads only.** Three tables consulted per export:

- `issues` (findings) — filtered by severity / status.
- `rule_runs` — aggregated when `coverage=1`.
- `finding_reproductions` — referenced per finding for curl synthesis.

No project-state keys, no "last exported" cache. Reports are always
fresh.

## CLI

No CLI export today — exports are HTTP-only. To script:

```
curl -sSf 'http://127.0.0.1:8787/reporter/export.json?status=open' > findings.json
```

## Troubleshooting

| Symptom                                              | Cause                                                                  | Fix                                                                                              |
|------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `/export.docx` returns 400                            | `python-docx` not installed                                             | `pip install python-docx`. Or pick Markdown / HTML / JSON / SARIF.                                |
| HTML report is huge (5-10× the Markdown)              | CSS is inlined for portability                                          | Use Markdown for size-sensitive distribution, HTML when self-containedness matters.               |
| Email client stripped the styling                     | Some webmail strips `<style>` blocks                                    | Send as attachment, or convert to PDF, or switch to Markdown rendered by the recipient.           |
| `severity=High` returned nothing                      | Severities are lowercase                                                | Use `severity=high`.                                                                              |
| No curl section for some findings                     | `reproduction_token` is null or its row is gone from `finding_reproductions` | Re-run the scan or add a manual reproducer; the report silently skips the section when absent. |
| Coverage section absent                               | `coverage=1` not in the query string                                    | Tick the checkbox on the index page, or append `&coverage=1` to the URL.                          |
| Classification text broke the Word layout             | No length validation                                                    | Keep it under a line; multi-line banners overflow the page header.                                |

## Test contract

Core (`reqlore/tests/unit/test_findings_and_reporter.py`):

- `test_render_markdown_includes_severity_sections` — H2 per severity, H3 per finding.
- `test_render_html_is_self_contained` — no `<link>` / `<script>`; evidence HTML-escaped.
- `test_render_docx_produces_valid_zip` — DOCX bytes start with `PK` ZIP magic.

Advanced (`reqlore/tests/unit/test_reporter_a4.py`) covers UTC handling,
severity bucketing, request-blob parsing, curl synthesis (drops Host /
Content-Length, quotes values), all-new-field rendering across Markdown
/ HTML / DOCX, JSON schema shape, SARIF top-level structure, SARIF
level mapping.

Route smoke (`reqlore/tests/unit/test_reporter_bp_a4.py`):

- `test_export_json_route_returns_versioned_schema` — `application/json`, schema key present.
- `test_export_sarif_route_returns_sarif210` — `application/sarif+json`, version key.
- `test_export_md_with_coverage_and_classification` — query params honoured.
- `test_reporter_index_lists_json_and_sarif_links` — links surfaced on the index page.
- `test_export_unknown_format_returns_404` — unknown extensions 404.
