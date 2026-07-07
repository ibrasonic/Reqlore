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
| `/jwt/keys/<id>/jwks.json` | GET | Serve a hosted attacker **JWK Set** (public half only) for the `jku` sink. Unauthenticated and free of any allow-list/SSRF guard by design — the *target server* fetches it, and testers legitimately point `jku` at localhost / lab IPs. Every fetch is logged to [History](history.md) as `jwt/jwks-host`. Unknown ids 404. |

## Form fields

| Field                       | Type      | Default                                       | Notes                                                                                 |
|-----------------------------|-----------|-----------------------------------------------|---------------------------------------------------------------------------------------|
| Compact JWT                 | textarea  | empty                                          | Header.payload.signature, dot-separated. 4 rows. `autocomplete="off"`.                |
| Algorithm                   | select    | `HS256`                                        | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `none`. |
| Header JSON                 | textarea  | empty                                          | Auto-filled on Decode. Must be valid JSON when signing.                                |
| Payload JSON                | textarea  | empty                                          | Auto-filled on Decode. Must be valid JSON when signing.                                |
| HMAC secret (HS*)           | input     | empty                                          | Required for HS* sign. `autocomplete="off"`.                                           |
| Private key PEM (RS*/ES*)   | textarea  | empty                                          | Required for RS*/ES* sign. Auto-filled by **Generate attacker key**.                    |
| Key type (attacker key)     | select    | `RSA-2048`                                     | `RSA-2048` (RS256) or `EC P-256` (ES256). Which keypair **Generate attacker key** mints. |
| Advertise via (attacker key)| select    | `jwk`                                          | `jwk` (embed the public key in the header) or `jku` (host a JWK Set and point the header's `jku` at it). |
| Public key (key confusion)  | textarea  | empty                                          | **Smart input** — accepts a PEM, a single JWK (`{"kty":"RSA",...}`), a full JWKS document (`{"keys":[...]}`), or a `https://.../jwks.json` **URL** (fetched through Reqlore's normal logged HTTP path, `engine=jwt/jwks-fetch` in History). The token's `kid` header auto-selects the matching JWKS entry; otherwise the first RSA key wins. Only `http://` and `https://` URLs are followed; redirects disabled; 10-second timeout; body cap 1 MB; paste cap 128 KB. |
| kid candidates              | textarea  | `kid1\nkey-1\n../../keys/x\n/dev/null`         | One per line. Empty lines dropped. Default set is a traversal payload.                 |

## Actions

| Button                        | What it does                                                                                                       |
|-------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **Decode (no verify)**        | Split the token, base64url-decode header and payload, fill the JSON fields, render `summarise_jwt()` one-liner. No signature check. |
| **Produce alg=none variant**  | Decode unverified, set header `alg` to `"none"`, re-encode without signature. Output: `<header>.<payload>.` (trailing dot, empty signature). |
| **Sign**                      | Re-encode header + payload with the chosen algorithm. HS* uses the secret field; RS*/ES* uses the private key field. `alg=none` produces an unsigned token. |
| **Generate attacker key**     | Mint (or reuse) an ephemeral keypair for the session, write its PKCS8 private-key PEM into *Private key PEM*, and set *Algorithm* to `RS256` (RSA) or `ES256` (EC). With **Advertise via = jwk** the public key is injected as a `jwk` header member (creating/replacing it, leaving the rest of the header intact). With **jku** a JWK Set is published at `/jwt/keys/<id>/jwks.json` and the header's `jku` is pointed at it (plus a matching `kid`). Finish the forge with **Sign** — nothing about signing changes. Reused across presses so the signed token stays consistent with the embedded/hosted key. |
| **Forge HS256-of-pubkey (key confusion)** | Decode current token, set `alg` to `HS256`, and HMAC-sign the header.payload with the server's RSA **public key bytes** as the HMAC secret. Signing bypasses PyJWT (which since 2.4 refuses to use an asymmetric key as HMAC secret) and uses `hmac.new(pem_bytes, ..., sha256)` directly — exactly the operation a vulnerable server performs when it picks the verifier by the token's `alg` header. The public-key field accepts PEM, JWK, JWKS, or a JWKS URL (see *Smart key input* below). |
| **Build kid set (kid traversal)** | Generate one HS256-signed variant per `kid` candidate — same payload, different `kid` header. Used against servers that fetch keys by `kid` from a filesystem path. |

## Algorithms

| Family | Algorithms                | Key field                  | Notes                                                |
|--------|---------------------------|----------------------------|------------------------------------------------------|
| HMAC   | `HS256`, `HS384`, `HS512` | HMAC secret                | Shared secret.                                       |
| RSA    | `RS256`, `RS384`, `RS512` | Private key PEM            | RSA-PKCS1-v1_5.                                       |
| ECDSA  | `ES256`, `ES384`, `ES512` | Private key PEM            | Curves: P-256 / P-384 / P-521.                        |
| None   | `none`                    | (none)                     | Produces `<header>.<payload>.` (trailing dot).        |

## Smart key input (RS→HS forge)

The **Public key** field on the RS→HS key-confusion action accepts four
formats. Detection is content-based (not a mode selector), so a plain PEM
still behaves exactly as it did before:

| Input starts with                        | Treated as | What happens                                                                                                                                                     |
|------------------------------------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-----BEGIN `                            | PEM        | Passed through verbatim to the HMAC signer. Label: **PEM (as-provided)**.                                                                                        |
| `{"kty":"RSA",…}`                        | JWK        | Converted to SPKI PEM via `RSAAlgorithm.from_jwk()` + `SubjectPublicKeyInfo`. Label: **JWK**.                                                                    |
| `{"keys":[…]}`                           | JWKS       | If the token's header carries a `kid`, the matching JWK is picked (error if it names a non-RSA key). Otherwise the first RSA key wins. Label: **JWKS (N keys, kid=…)** or **JWKS (N keys, first RSA key)**. |
| `http://…` or `https://…`                | JWKS URL   | Fetched through Reqlore's normal HTTP path (`engine=jwt/jwks-fetch` in [History](history.md)), then treated as JWKS. Label: **JWKS URL (N keys, kid=…)**.        |

Every other input (including `file://…`, `ftp://…`, `javascript:…`,
`data:…`, scheme-relative `//…`, and arbitrary text) is **rejected** with
a visible error before any parsing or I/O.

### Security guards

The public-key input is treated as untrusted — a pentester might paste
material copied verbatim from an engagement target. The resolver
enforces:

- **Scheme allow-list.** Only `http://` and `https://` URLs are ever
  fetched. `file://`, `ftp://`, `gopher://`, `javascript:`, `data:` and
  any other scheme are rejected with *"Only http:// and https:// URLs
  are allowed (got scheme=X)."* — visible in the workbench so the
  security decision is not hidden.
- **Redirects disabled.** The httpx call runs with
  `follow_redirects=False`, so a JWKS URL cannot be redirected into a
  disallowed scheme or an internal host the tester didn't approve.
- **Timeout.** 10 seconds for the whole fetch.
- **Size caps.** Pasted input capped at 128 KB; fetched body capped at
  1 MB. Larger payloads are rejected before any JSON parsing.
- **Key-type gate.** Only `kty="RSA"` is accepted. `EC`, `OKP`, and
  `oct` keys are rejected with a message that names the kty.
- **Kid gating.** When the token carries a `kid`, the resolver only
  picks the JWK with that exact `kid`. If it isn't in the JWKS, the
  error lists the available kids so the operator can spot the mismatch.
- **History logging.** Every JWKS-URL fetch is written into
  `http_history` (engine `jwt/jwks-fetch`) with full raw request and
  response — the tester always sees what Reqlore fetched on their
  behalf.
- **Bounded error messages.** Any user-provided fragment (URL, kid) is
  truncated to 120 chars before appearing in an error message; all
  error text is Jinja-escaped by the workbench template.

### Why the signer bypasses PyJWT

PyJWT ≥ 2.4 refuses to use an asymmetric key as an HMAC secret
(`InvalidKeyError: The specified key is an asymmetric key or x509
certificate and should not be used as an HMAC secret.`) — a defensive
block against exactly this footgun in normal apps. For the workbench
that block would prevent the tester from reproducing the attack a
vulnerable server performs. The blueprint therefore uses
`hmac.new(pem_bytes, signing_input, sha256)` directly, matching what a
vulnerable server does. This is the only place in Reqlore where PyJWT
is bypassed for signing.

## Attacker key (jwk / jku header injection)

Exploiting the `jwk` (embedded-key) and `jku` (remote key-set URL) header
sinks used to be the one part of the workbench that forced you out to
external tooling — generate an RSA/EC keypair with `openssl`/`node`,
hand-paste the halves, and for `jku` stand up your own `python -m
http.server` to host a JWK Set. **Generate attacker key** collapses all of
that into one button, mirroring how the smart *Public key* input collapsed
RS→HS confusion.

| Advertise via | What the button does                                                                                                                                                   |
|---------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **jwk**       | Mints the keypair, writes its private PEM into *Private key PEM*, sets *Algorithm*, and injects the public JWK as a `jwk` member of the header JSON (removing any `jku`). This is the embedded-key attack: a server that trusts the token's own `jwk` will verify against your key. |
| **jku**       | Same keypair wiring, but publishes `{"keys":[<public JWK with a random kid>]}` at `http://<ui-host>:<ui-port>/jwt/keys/<id>/jwks.json` and writes that URL into the header's `jku` (plus the matching `kid`, removing any `jwk`). A server that fetches keys from the token's `jku` will fetch *yours*. |

After pressing it, the output panel confirms exactly what happened — e.g.
*"Attacker key generated (RSA-2048); public half embedded as jwk."* or
*"…JWK Set hosted at http://127.0.0.1:8787/jwt/keys/ab12/jwks.json."* Then
press **Sign** to produce the forged token.

### Security & scope

- The keypair is **ephemeral** and lives only in this process (never on
  disk, never in the signed session cookie), keyed by your browser
  session. It is **reused across presses** so the token you sign matches
  the key you embedded/hosted. Switching *Key type* mints a fresh key; the
  hosted `jku` URL stays stable across presses.
- The hosted endpoint serves **only the generated public JWK Set** — the
  private key never leaves the workbench page.
- The endpoint is intentionally **unauthenticated and has no allow-list /
  SSRF guard**: the *target server* is what fetches it, and testers
  legitimately point `jku` at `127.0.0.1` and lab IPs. It binds on the
  same interface as the UI (a `0.0.0.0` bind, e.g. under Docker, is
  rewritten to `127.0.0.1` so the URL is actually fetchable locally).
- Both the **publish** (method `PUT`) and every **target fetch** (method
  `GET`) are logged to [History](history.md) as `jwt/jwks-host`, alongside
  the smart-input's `jwt/jwks-fetch`.
- Errors are field-prefixed and specific — never a bare 500. Missing/invalid
  advertise choice → *"Choose an advertise-via option (jwk or jku)."*;
  a host-endpoint failure → *"Could not start the key-host endpoint on
  <url>."*

## Accessibility notes

- Main form `aria-label="JWT operations"`. Errors render in `<p role="alert">`.
- A `class="section-nav"` landmark (`aria-label="JWT workbench sections"`) at
  the top provides in-page jump links to the four numbered fieldsets
  (Decode, Re-sign &amp; forge, Key confusion, kid traversal) — a bypass-block
  for keyboard and screen-reader users.
- Each output block is a `<section aria-labelledby="…">` — `j-dec` decoded,
  `j-an` alg=none, `j-atk-out` attacker key (also `role="status"`), `j-sg`
  signed token, `j-kc` key confusion, `j-ks` kid set.
- Numbered fieldsets with legends: *1. Decode*, *2. Re-sign &amp; forge*
  (which nests a *Generate attacker key (jwk / jku)* fieldset), *3. RS→HS key
  confusion*, *4. kid traversal*.
- Every control has a programmatically-associated `<label>`; help text is
  wired with `aria-describedby` (`j-tok-help`, `j-pk-help`, `j-atk-help`,
  `j-pub-help`). The attacker-key controls are wrapped in a
  `role="group"` described by `j-atk-help`.
- kid set output is a real `<table>` with `<caption>`, `<thead>`, `<th scope="col">`.
- JSON blocks render as `<pre><code>` (code semantics, no AAA contrast trap).
- Read order: section nav → numbered fieldsets → conditional outputs.

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

Decode the RS256 token. In the **Public key** box paste **any one** of:

- the PEM you got from the target (`-----BEGIN PUBLIC KEY-----`);
- a single JWK copied from `/.well-known/jwks.json`
  (`{"kty":"RSA","n":"...","e":"AQAB","kid":"..."}`);
- the full JWKS document verbatim (`{"keys":[...]}`);
- the JWKS **URL** itself (`https://target/.well-known/jwks.json`) —
  Reqlore fetches it through the normal logged HTTP path so the GET
  shows up in [History](history.md) tagged `jwt/jwks-fetch` with the
  full raw request / response.

Click **Forge HS256-of-pubkey**. The output panel shows the forged
token and, above it, the resolved source label (e.g.
*"Key resolved from: JWKS URL (3 keys, kid=primary-2024). Converted
to SPKI PEM before HMAC-signing."*). If the server validates with the
same key for both RS256 and HS256, this token passes verification.

### 5. kid traversal

Decode. The default `kid` list already targets `/dev/null` and
`../../keys/x`. Add your own (one per line). Paste an HS256 secret.
**Build set**. The table lists one signed token per kid — try each
against the server's kid lookup endpoint.

### 6. jwk / jku header injection (attacker key)

Decode the target's RS/ES token so *Header JSON* and *Payload JSON* are
filled. In *2. Re-sign &amp; forge* → *Generate attacker key*:

- **Embedded (jwk):** set *Advertise via* = `jwk`, pick a *Key type*, press
  **Generate attacker key**. The private PEM lands in *Private key PEM* and
  a `jwk` member appears in the header. Press **Sign**. If the server
  trusts the token's own `jwk`, the forged token verifies.
- **Remote (jku):** set *Advertise via* = `jku`, press **Generate attacker
  key**. Reqlore hosts your public JWK Set and writes its URL into the
  header's `jku`. The confirmation panel prints the URL (also visible in
  [History](history.md) as `jwt/jwks-host`). Press **Sign**. When the
  target fetches that `jku`, it pulls *your* key and the token verifies —
  the fetch is logged too. Point the target at the printed URL (edit the
  host if your lab target can't reach `127.0.0.1`).

## Storage footprint

**None persistent.** Form state lives in PRGCache (32-entry LRU,
in-memory, per-process). Closing the tab loses it. No `.rlr` writes. The
attacker keypair and any hosted JWK Set also live only in memory (a
bounded per-session store, cleared on restart) — nothing is written to
disk. The publish/fetch of a hosted `jku` set *does* add rows to
`http_history` (engine `jwt/jwks-host`), like any other logged request.

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
| *"Public key: Only http:// and https:// URLs are allowed (got scheme=X)."* | The public-key field looked URL-shaped but used a disallowed scheme (`file://`, `javascript:`, `data:`, `//host/...`) | Paste an `http://` or `https://` URL, or the JWKS body inline.                                    |
| *"Public key: kid '…' not found in JWKS (available: …)"* | Token's `kid` header names a key the JWKS doesn't contain              | Check the target actually serves that JWKS; try the URL form so History records the raw JSON.     |
| *"Public key: Only RSA keys are supported for RS->HS forge (got kty=EC)."* | The kid pointed at an EC/OKP/oct JWK                                    | The target isn't RS-signing this token; use the normal **Sign** flow with an EC private key instead. |
| *"Public key: Fetched body exceeds 1024 KB limit."* | The URL served something huge (an HTML page, an error blob, a wrong endpoint) | Point at the actual JWKS endpoint; paste the JSON inline as a fallback.                          |
| *"Choose an advertise-via option (jwk or jku)."* | Pressed **Generate attacker key** without selecting an *Advertise via* value | Pick `jwk` or `jku` from the dropdown and press it again.                                        |
| *"Could not start the key-host endpoint on <url>."* | The in-memory JWK-Set host could not be created for the `jku` publish | Retry; if it persists, use `jwk` (embedded) mode, which needs no hosting.                        |
| `jku` URL shows `127.0.0.1` but the lab target can't reach it | The UI binds `0.0.0.0` (e.g. Docker) so Reqlore prints a loopback URL | Edit the `jku` host in *Header JSON* to an address your target can reach, then **Sign**.         |

## Test contract

- `reqlore/tests/unit/test_diff_and_jwt.py::test_jwt_summary_alg_none_warning` — `summarise_jwt()` flags `alg=none` in plain English.
- `reqlore/tests/unit/test_jwt_smart_key.py` — 41 cases covering the smart key input: format detection (PEM / JWK / JWKS / URL), kid selection, non-RSA rejection, scheme allow-list, size caps, JSON parse errors, fetch errors, URL logged into `http_history`, HTTP non-2xx surfaced as UI error, and end-to-end forge success for PEM, JWK, and JWKS inputs.
- `reqlore/tests/unit/test_jwt_attacker_key.py` — the `jwk` / `jku` attacker-key feature: embedded-jwk token verifies against the generated key; jku path hosts + serves the JWK Set and fetch-then-verify succeeds; both RSA-2048 and EC P-256; keypair reuse and stable jku URL across presses; key-type switch regenerates; the two named error cases return a friendly 200 (not 500); publish + fetch logged as `jwt/jwks-host`; unknown hosted id 404s; the served set never contains the private half.
- For Intruder's `jwt:` processor coverage, see `reqlore/tests/unit/test_intruder*.py`.
