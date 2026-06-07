# Weblore — Feature Matrix

Legend: ✅ shipped · 🚧 in progress · 📋 planned · — out of scope

## Core

| Feature | Status | Phase | Notes |
|---|---|---|---|
| Local web UI (Flask, 127.0.0.1) | ✅ | 1 | Themes light/dark/high-contrast/system |
| Project files (.weblore SQLite) | ✅ | 1 | Thread-safe; WAL; zlib blob compression |
| HTTP engine: httpx (H1/H2, mTLS, proxies) | ✅ | 1 | Default engine |
| HTTP engine: raw socket+ssl | ✅ | 1 | Byte-exact, no normalisation |
| HTTP engine: h2 frame-level | 📋 | 5 | For smuggling/priority |
| HTTP engine: h3/QUIC | 📋 | 5 | Optional |
| WS engine | 📋 | 4 | |
| curl render (Copy as curl) | ✅ | 1 | Export only |
| Plugin API + hot reload | 📋 | 3 | |
| CLI runner (YAML jobs) | 📋 | 5 | Same engines, no UI |
| Headless mode | 📋 | 5 | For CI |

## Proxy & Interception

| Feature | Status | Phase |
|---|---|---|
| MITM proxy (mitmproxy lib) | ✅ | 1 |
| Explicit + transparent modes | ✅ | 1 |
| TLS CA generation + export | ✅ | 1 |
| Intercept rules (host/method/status/CT) | ✅ | 1 |
| Hold queue with SR-friendly prompt | ✅ | 1 (async hold; sync hold Phase 2) |
| Match & Replace (req/resp, scoped) | 📋 | 2 |
| WS frame interception | 📋 | 4 |

## History & Targeting

| Feature | Status | Phase |
|---|---|---|
| HTTP history (search, filter, export) | 📋 | 1 |
| Sitemap (host tree, in/out scope) | 📋 | 2 |
| Logger++-style extended columns | 📋 | 2 |
| WS history | 📋 | 4 |
| Project search (regex across modules) | 📋 | 2 |

## Repeater

| Feature | Status | Phase |
|---|---|---|
| Send/edit/replay | 📋 | 1 |
| Paste curl → load request | 📋 | 1 |
| Paste raw HTTP → load request | 📋 | 1 |
| Tabbed history per request | 📋 | 1 |
| Diff against previous response | 📋 | 2 |

## Intruder

| Feature | Status | Phase |
|---|---|---|
| Sniper / Battering Ram / Pitchfork / Cluster Bomb | 📋 | 2 |
| Payload sources (list, file, brute, dates, numbers, common-pw) | 📋 | 2 |
| Payload processors (case, encode, hash, regex, prefix/suffix) | 📋 | 2 |
| Grep-match / grep-extract / grep-payloads | 📋 | 2 |
| Sortable results table (status/length/time) | 📋 | 2 |
| Per-host concurrency limiter | 📋 | 2 |

## Decoder / Encoder

| Feature | Status | Phase |
|---|---|---|
| URL / HTML / b64 / hex / gzip / deflate | ✅ | 1 |
| Form-body URL encode/decode (preserves `&` and `=`) | ✅ | 8 |
| JWT decode + sign (HS/RS/ES, alg=none) | ✅ | 2 |
| Unicode escapes / ROT-N | ✅ | 1 |
| MD5 / SHA1 / SHA-2 / HMAC | ✅ | 1 |
| Smart-decode (chained) | ✅ | 1 |

## Comparer

| Feature | Status | Phase |
|---|---|---|
| Word + byte diff with line numbers | 📋 | 2 |
| SR-friendly "in A / in B / changed" summary | 📋 | 2 |

## Scanner

| Feature | Status | Phase |
|---|---|---|
| Passive: security headers, mixed content, autocomplete-on-pw, CSP report-only, source maps, dir listing, sensitive files | 📋 | 3 |
| Active: XSS (reflected/stored), SQLi (error/time), OS-cmd, SSRF (+OAST), open redirect, host-header inj, XXE, proto-pollution, GraphQL introspection, JWT alg=none, SSTI fingerprint | 📋 | 4 |
| Per-finding CWE + OWASP + reproducer | 📋 | 3 |

## Specialised modules

| Feature | Status | Phase |
|---|---|---|
| JWT workbench (decode/sign/alg-switch/key-confusion/kid traversal) | 📋 | 2 |
| SAML inspector + signature-wrapping helper | 📋 | 4 |
| GraphQL workbench (intro, schema explorer, batch) | 📋 | 4 |
| Content discovery (wordlist, depth, filters) | 📋 | 4 |
| Param miner (header/cookie/param brute via length oracle) | 📋 | 4 |
| Sequencer (entropy, FIPS bit tests, chi-square) | 📋 | 5 |
| CSRF PoC generator | 📋 | 4 |
| Clickjacking tester | 📋 | 4 |
| OAST (interactsh / self-hosted) | 📋 | 5 |

## Session handling

| Feature | Status | Phase |
|---|---|---|
| Macro recorder | 📋 | 4 |
| Auto re-auth on 401/expired marker | 📋 | 4 |
| Per-module rules | 📋 | 4 |

## Reporting

| Feature | Status | Phase |
|---|---|---|
| Markdown / HTML / DOCX per finding | 📋 | 3 |
| Per-finding severity + CVSS 3.1 | 📋 | 3 |
| Bundled request/response pairs | 📋 | 3 |

## Accessibility-only additions

| Feature | Status | Phase |
|---|---|---|
| Plain-language response summarizer | 📋 | 1 |
| Verbosity profiles (Concise/Standard/Verbose) | 📋 | 1 |
| Optional audio cues (off by default) | 📋 | 2 |
| Keyboard-map self-test page | 📋 | 1 |
| "Explain this request/response" deterministic | 📋 | 2 |
| Tabular "Read as list" alt-view | 📋 | 1 |
| Copy as: curl / httpx / requests / raw / fetch | 📋 | 1 |
