# SAML inspector — `/saml/`

Decode a SAML payload (raw XML, HTTP-POST base64, or HTTP-Redirect
DEFLATE), pretty-print the XML, and surface the usual SAML misconfigs:
unsigned messages, weak crypto algorithms, missing expiry, missing
audience, XML comments (XSW family).

## Where it is

- **URL:** `/saml/`
- **Nav:** *SAML* in the top bar.
- Single page; PRG-cached result under `?t=<token>`.

## Quick start

1. Capture a SAML Response from the browser DevTools (form-encoded base64
   value, or query-string DEFLATE for HTTP-Redirect, or raw XML).
2. Open `/saml/`. Paste the payload into **SAML payload**.
3. **Inspect**. Summary + findings + pretty-printed XML render below.

## Routes

| URL       | Method | What it does                                                       |
|-----------|--------|--------------------------------------------------------------------|
| `/saml/`  | GET    | Render form. Hydrate from `?t=<token>` (PRG cache).                 |
| `/saml/`  | POST   | Decode, parse, audit, render. Stash in PRGCache, 302 to `?t=<token>`. |

## Form fields

| Field   | Type     | Default | Notes                                              |
|---------|----------|---------|----------------------------------------------------|
| `blob`  | textarea | empty   | **Required.** Base64, raw XML, or DEFLATE-encoded. |

## Decode order

`decode(blob)` tries three bindings in this order and returns the first
that succeeds (along with the binding name):

1. **Raw XML** — input starts with `<`. Parse directly.
2. **HTTP-POST** — base64 → UTF-8. Padding auto-corrected
   (`(-len(s)) % 4` `=` characters appended).
3. **HTTP-Redirect** — raw DEFLATE (no zlib header) → UTF-8.

If none succeed, raises `ValueError`.

## Parsed fields

Via `xml.etree.ElementTree.fromstring()` with local-name matching
(namespace prefixes stripped):

- `Issuer` text.
- `Destination` attribute.
- `ID` attribute.
- `Conditions/NotOnOrAfter` attribute.
- `Conditions/AudienceRestriction/Audience` text.

## Findings (heuristics)

| Severity | Title                                            | Detection                                                                 | rule_id              | CWE     |
|----------|--------------------------------------------------|---------------------------------------------------------------------------|----------------------|---------|
| HIGH     | SAML message is not signed                       | No `<Signature>` element (presence only — no crypto verification).         | `saml:unsigned`      | CWE-345 |
| MEDIUM   | Weak cryptographic algorithm: SHA1 / MD5         | Regex match for `#sha1`, `-sha1`, `#md5`, `-md5` in the XML.               | `saml:weak-algo`     | CWE-327 |
| MEDIUM   | No expiry (NotOnOrAfter) on assertion             | `Conditions/NotOnOrAfter` attribute missing.                                | `saml:no-expiry`     | CWE-294 |
| MEDIUM   | No AudienceRestriction                            | `AudienceRestriction` element missing.                                      | `saml:no-audience`   | CWE-346 |
| LOW      | XML comments in payload                          | Regex match for `<!--…-->` — CVE-2018-0489 family hint.                     | `saml:xml-comments`  | CWE-91  |

`record_saml_findings()` writes these into the project's findings
table.

> **Heuristics only.** Signature presence is not cryptographic
> validation. Algorithm detection is regex-based; expect false
> positives if the string appears in a comment or unrelated attribute.

## Pretty-print

`xml.dom.minidom.parseString()` with 2-space indent. On parse error,
falls back to the raw XML.

## Accessibility notes

- `<label for="blob">` on the textarea.
- Summary section uses `<dl>` / `<dt>` / `<dd>` for key/value pairs.
- Findings render as `<ul>` of `<li>`.
- Pretty-printed XML inside `<details><pre>` for progressive disclosure.
- Errors render as a leading `<strong>Error:</strong> <msg>`.

## How it integrates

**Producers:** none — paste-only.

**Consumers:** the `record_saml_findings()` helper records into the
findings table; otherwise self-contained.

## Recipes

### Inspect an HTTP-POST SAML Response

Copy the `SAMLResponse` form-field value. Paste. **Inspect**. Decoder
detects `http-post`.

### Inspect an HTTP-Redirect SAML AuthnRequest

Copy the `SAMLRequest` query-string value (DEFLATE-encoded + base64-encoded).
Paste. The DEFLATE branch reconstructs the XML.

### Confirm a missing signature

Strip the `<Signature>` element from a known-good Response. Paste. You
get the HIGH `saml:unsigned` finding.

### Spot SHA-1 use

Look for `<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>`
in the XML — the inspector flags it MEDIUM.

### Trigger the XSW hint

Add an XML comment anywhere in the payload (`<!-- foo -->`). The LOW
`saml:xml-comments` finding fires (CVE-2018-0489 family).

## Storage footprint

**No persistent storage** for the workbench itself. PRGCache holds the
last form blob and `SAMLInspection` result under a token (in-memory).

`record_saml_findings()` does write to the `issues` table when invoked
— but the inspector UI does not call it automatically; that's an
integration helper.

## CLI

No CLI surface.

## Troubleshooting

| Symptom                                              | Cause                                                                  | Fix                                                                                              |
|------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Decode succeeds but binding is wrong                 | Auto-detection tries Raw → POST → Redirect in order                     | Re-paste without any wrapping (no padding fixes needed — the decoder handles missing `=`).        |
| Pretty-print missing                                  | XML parse failure                                                       | Look for the `<strong>Error:</strong>` line — raw XML still rendered.                             |
| `saml:weak-algo` false positive                       | Regex matches `#sha1` in a comment / unrelated string                   | Inspect the pretty-printed XML; ignore if not in a SignatureMethod / DigestMethod.                |
| `saml:unsigned` doesn't mean what you think           | Presence check only — no validation that the signature actually matches | Use a real SAML toolkit (python3-saml, etc.) for cryptographic verification.                      |
| `AudienceRestriction` flagged on AuthnRequest         | Audience is on Response, not Request                                    | Expected — the rule fires when the payload is a Response without audience. Suppress for Requests. |

## Test contract

- `reqlore/tests/unit/test_web_smoke_phase4.py::test_saml_index` — page renders.
- `…::test_saml_decode_post` — POST with base64-encoded Response → 200, binding `http-post`, issuer extracted.
- `reqlore/tests/unit/test_producer_helpers_emission.py::test_saml_helper_writes_findings` — `record_saml_findings()` writes the three expected findings with correct rule IDs + CWE codes.
