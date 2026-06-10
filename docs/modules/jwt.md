# JWT workbench — `/jwt/`

Decode, re-sign, forge, and attack JSON Web Tokens. Works on any JWT —
the [Proxy](proxy.md) and [History](history.md) send-to menus open this
page pre-filled when the request carries a Bearer token.

For per-payload signing inside an [Intruder](intruder.md) attack, see the
`jwt:` processor in [intruder.md](intruder.md#processors).

## Where it is

- **URL:** `/jwt/`
- **Nav:** *JWT* in the top bar.
- Single-page workbench — no tabs.

## Quick start

1. From [History](history.md) row Actions menu → **Send to JWT** (Alt+J). The token arrives pre-filled.
2. Click **Decode (no verify)** — header and payload appear as JSON, plus a one-sentence summary.
3. Edit the payload JSON in place (e.g. flip `"role":"user"` → `"admin"`).
4. Either **Produce alg=none variant** (no key needed) or paste a secret / key and **Sign**.
5. Copy the new token from the output panel back into your target.

## Routes

| URL      | Method | What it does                                                                          |
|----------|--------|---------------------------------------------------------------------------------------|
| `/jwt/`  | GET    | Render the workbench. Prefill from `?token=<jwt>` (link from Send-to) or `?t=<token>` (PRG cache). |
| `/jwt/`  | POST   | Run an action. Stash result in PRGCache, 302 to `?t=<cache-token>` (no resubmit on refresh). |

## Form fields

| Field                       | Type      | Default                                       | Notes                                                                                 |
|-----------------------------|-----------|-----------------------------------------------|---------------------------------------------------------------------------------------|
| Compact JWT                 | textarea  | empty                                          | Header.payload.signature, dot-separated. 4 rows. `autocomplete="off"`.                |
| Algorithm                   | select    | `HS256`                                        | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `none`. |
| Header JSON                 | textarea  | empty                                          | Auto-filled on Decode. Must be valid JSON when signing.                                |
| Payload JSON                | textarea  | empty                                          | Auto-filled on Decode. Must be valid JSON when signing.                                |
| HMAC secret (HS*)           | input     | empty                                          | Required for HS* sign. `autocomplete="off"`.                                           |
| Private key PEM (RS*/ES*)   | textarea  | empty                                          | Required for RS*/ES* sign.                                                             |
| Public key PEM (key confusion) | textarea | empty                                       | RSA public key in PEM. Used to forge HS256-of-pubkey.                                  |
| kid candidates              | textarea  | `kid1\nkey-1\n../../keys/x\n/dev/null`         | One per line. Empty lines dropped. Default set is a traversal payload.                 |

## Actions

| Button                        | What it does                                                                                                       |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **Decode (no verify)**        | Split the token, base64url-decode header and payload, fill the JSON fields, render `summarise_jwt()` one-liner. No signature check. |
| **Produce alg=none variant**  | Decode unverified, set header `alg` to `"none"`, re-encode without signature. Output: `<header>.<payload>.` (trailing dot, empty signature). |
| **Sign**                      | Re-encode header + payload with the chosen algorithm. HS* uses the secret field; RS*/ES* uses the private key field. `alg=none` produces an unsigned token. |
| **Forge HS256-of-pubkey (key confusion)** | Decode current token, set `alg` to `HS256`, sign with the server's RSA **public key** as if it were an HMAC secret. If the server verifies with the same key for both RS256 and HS256, this token passes. |
| **Build kid set (kid traversal)** | Generate one HS256-signed variant per `kid` candidate — same payload, different `kid` header. Used against servers that fetch keys by `kid` from a filesystem path. |

## Algorithms

| Family | Algorithms                | Key field                  | Notes                                                |
|--------|---------------------------|----------------------------|------------------------------------------------------|
| HMAC   | `HS256`, `HS384`, `HS512` | HMAC secret                | Shared secret.                                       |
| RSA    | `RS256`, `RS384`, `RS512` | Private key PEM            | RSA-PKCS1-v1_5.                                       |
| ECDSA  | `ES256`, `ES384`, `ES512` | Private key PEM            | Curves: P-256 / P-384 / P-521.                        |
| None   | `none`                    | (none)                     | Produces `<header>.<payload>.` (trailing dot).        |

## Accessibility notes

- Main form `aria-label="JWT operations"`. Errors render in `<p role="alert">`.
- Each output block is a `<section aria-labelledby="…">` — `j-dec` decoded,
  `j-an` alg=none, `j-sg` signed token, `j-kc` key confusion, `j-ks` kid set.
- Logical fieldsets with legends: *Input token*, *Re-sign*, *RS→HS key
  confusion*, *kid traversal*.
- kid set output is a real `<table>` with `<caption>`, `<thead>`, `<th scope="col">`.
- JSON blocks render as `<pre><code>` (code semantics, no AAA contrast trap).
- Read order: form → action buttons → conditional outputs in the order
  above.

## How it integrates

**Producers** (what feeds JWT):

- [History](history.md) detail page + row Actions menu — **Send to JWT** (Alt+J).
  Only visible when the request has `Authorization: Bearer <jwt-shaped>`.
- [Proxy](proxy.md) intercept detail — same Alt+J. Same visibility rule.

**Consumers:** none — the workbench is a sink. Copy tokens back into
[Repeater](repeater.md) or your target by hand.

**Related:** the `jwt:` processor in [Intruder](intruder.md#processors)
signs per-payload at attack time (HS/RS/ES, target=`json` or `header`,
secret literal or `secret=$secret`).

## Recipes

### 1. Decode and inspect a token

Paste the token. Click **Decode (no verify)**. Read the header, payload,
and the one-line summary (`"JWT signed with HS256; subject 'alice';
expires in 3600 seconds"`).

### 2. Re-sign with HS256 after editing a claim

Decode. Edit `payload_text` (e.g. flip `"role":"user"` → `"admin"`). Pick
`HS256`. Paste the secret. **Sign**. Copy the new token.

### 3. alg=none downgrade

Decode. **Produce alg=none variant**. Send the resulting
`<header>.<payload>.` token — if the server accepts unsigned tokens,
you're in.

### 4. RS→HS key confusion

Decode the RS256 token. Paste the server's RSA public key into the
**Public key PEM** box. **Forge HS256-of-pubkey**. Send the forged token.
If the server validates with the same key for both RS256 and HS256, it
passes verification.

### 5. kid traversal

Decode. The default `kid` list already targets `/dev/null` and
`../../keys/x`. Add your own (one per line). Paste an HS256 secret.
**Build set**. The table lists one signed token per kid — try each
against the server's kid lookup endpoint.

## Storage footprint

**None persistent.** Form state lives in PRGCache (32-entry LRU,
in-memory, per-process). Closing the tab loses it. No `.rlr` writes.

## CLI

No CLI equivalent — the workbench is web-only. For per-payload signing in
a scripted attack, use the Intruder `jwt:` processor (see
[Intruder Processors](intruder.md#processors)) and run via:

```
reqlore intruder run --project <p> <attack-id>
```

## Troubleshooting

| Symptom                                           | Cause                                                                  | Fix                                                                                              |
|---------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| Forged token rejected by server                   | Server uses a different key, or HS-vs-RS is split server-side          | Re-extract the public key from `/.well-known/jwks.json` and paste verbatim.                       |
| **Sign** errors on `header_text` / `payload_text` | Not valid JSON                                                          | Fix the JSON — pretty-print via [Decoder](decoder.md) → `json_pretty` if you got lost.            |
| kid traversal generated only HS256 tokens          | Working as designed — the action hard-codes HS256                       | For RS256 kid traversal, sign each kid variant by hand (Decode → edit `kid` → Sign).              |
| **Send to JWT** missing from row menu             | Request had no `Authorization: Bearer <jwt-shaped>`                     | Paste the token directly into the *Compact JWT* field.                                            |
| Whitespace in a kid silently disappears           | kid lines are stripped and empty-line-dropped                          | Encode the whitespace (`%20`) or use a different attack vector.                                   |
| Decoded JSON has the wrong claims                 | You decoded the original; you forgot to **Sign** after editing          | After every edit to `payload_text`, click **Sign** before copying.                                |

## Test contract

- `reqlore/tests/unit/test_diff_and_jwt.py::test_jwt_summary_alg_none_warning` — `summarise_jwt()` flags `alg=none` in plain English.
- For Intruder's `jwt:` processor coverage, see `reqlore/tests/unit/test_intruder*.py`.
