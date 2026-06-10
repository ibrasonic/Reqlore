# WebSocket workbench — `/ws/`

Open a WebSocket connection, send text or binary frames, capture every
frame in / out, save the transcript to the project, replay-by-sending
more frames to an open transcript. Requires the optional `websockets`
extra.

## Where it is

- **URL:** `/ws/`
- **Nav:** *WebSocket* in the top bar.
- Per-project — transcripts persist in `project_state`.

## Quick start

1. Open `/ws/new`. Paste a WebSocket URL (e.g. `wss://echo.websocket.org/`).
2. Add headers if the server needs them.
3. Optional: first message — text or binary (binary expects hex input).
4. Pick **Recv seconds** (default 2 s).
5. **Connect**. The transcript appears with every sent + received frame.
6. From the transcript page, send more frames into the same URL with **Send**.

## Routes

| URL                  | Method | What it does                                                            |
|----------------------|--------|-------------------------------------------------------------------------|
| `/ws/`               | GET    | List every saved transcript (newest id last).                            |
| `/ws/new`            | GET    | Render the new-session form.                                             |
| `/ws/new`            | POST   | Connect → send optional first message → recv for N seconds → save.       |
| `/ws/<tid>`          | GET    | Render a transcript with its message table.                              |
| `/ws/<tid>/send`     | POST   | Reconnect to the same URL → send another message → append to transcript. |
| `/ws/<tid>/delete`   | POST   | Drop the transcript from `project_state`.                                |

## Form fields (new session)

| Field          | Type     | Default     | Notes                                                                                  |
|----------------|----------|-------------|----------------------------------------------------------------------------------------|
| `url`          | url      | empty       | **Required.** `wss://` or `ws://`.                                                      |
| `headers`      | textarea | empty       | One per line `Name: value`. Sent on the WebSocket handshake.                            |
| `kind`         | radio    | `text`      | `text` (UTF-8) or `binary` (hex input).                                                 |
| `data`         | textarea | empty       | First message body. For `binary`, hex (`48656c6c6f` = "Hello").                         |
| `recv_seconds` | number   | `2`         | Seconds to wait for incoming frames after sending. Range 0 – 60, step 0.5.              |

The send-more form on a transcript page has the same `kind` / `data` /
`recv_seconds` fields.

## Behaviour

- **Connect:** `websockets.sync.client.connect(url, additional_headers=…, open_timeout=15.0)`.
- **Send:**
  - Text: `ws.send(data)` (UTF-8 string).
  - Binary: `bytes.fromhex(data)` → `ws.send(<bytes>)`. Invalid hex raises `ValueError`.
- **Recv loop:** monotonic-clock timed for `recv_seconds`; each `ws.recv(timeout=remaining)` runs until `TimeoutError`. Cleanly closes when the loop ends. Exceptions during recv land in the transcript as a `[error] <msg>` row.
- **Frame logging:** every send/recv produces a `WSMessage(direction, ts, kind, data, size)`:
  - `direction` — `"send"` or `"recv"`.
  - `kind` — `"text"` (UTF-8 string stored as-is) or `"binary"` (bytes base64-encoded for storage).
  - `size` — UTF-8 byte length (text) or decoded byte length (binary).

## Transcript JSON

Stored in `project_state["ws:<id>"]`:

```json
{
  "url": "wss://example.com/socket",
  "notes": "",
  "closed": true,
  "messages": [
    {"dir": "send", "ts": 1730000000, "kind": "text", "data": "hello", "size": 5},
    {"dir": "recv", "ts": 1730000001, "kind": "text", "data": "hello", "size": 5}
  ]
}
```

ID counter at `project_state["ws:next_id"]`. Iteration walks `1` to
`next_id - 1`.

## Accessibility notes

- Every input has `<label for="…">` — `url`, `hdr`, `k-text`, `k-bin`, `d`, `rs`.
- Message-type radios grouped in `<fieldset><legend>`.
- Transcript table: `<th scope="col">` headers; direction column uses
  `<th scope="row">`.
- Headings `<h1>` page, `<h2>` per section.
- Errors render in the global flash region.

## How it integrates

**Producers / consumers:** none — workbench is standalone. Transcripts
don't feed [Repeater](repeater.md) or [Intruder](intruder.md). To
replay a frame, copy it manually.

## Recipes

### Echo-test against a public server

URL: `wss://echo.websocket.org/`, Kind: Text, Data: `hello`, Recv: 2s,
**Connect**. The transcript shows your `send` and the server's `recv`.

### Send binary as hex

Kind: Binary, Data: `48656c6c6f` (= "Hello"). Server-side receives
`b"Hello"`. Binary inbound frames render as base64 in the transcript.

### Authenticated handshake

Headers:

```
Authorization: Bearer eyJhbGciOi...
```

The WebSocket handshake will carry the header.

### Append a frame to an open transcript

From `/ws/<tid>`, fill the send-more form, click **Send**. Headers on
the original connect are not reused — only the URL.

### Watch a long-lived feed

`recv_seconds=30`. Transcript captures every push frame the server
emits in that window.

## Storage footprint

- `project_state["ws:<id>"]` — JSON transcript per session.
- `project_state["ws:next_id"]` — counter; bumped on each save.

No db table, no in-memory cache.

## CLI

No CLI. Driving a WebSocket from scripts is out of scope — use the
Python `websockets` library directly.

## Troubleshooting

| Symptom                                                  | Cause                                                                  | Fix                                                                                              |
|----------------------------------------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| "websockets is not installed"                             | Optional dependency missing                                             | `pip install reqlore[websocket]` (or `pip install websockets`).                                  |
| "ValueError: non-hexadecimal" on binary send              | Binary input must be hex                                                | Hex-encode first (e.g. with [Decoder](decoder.md) `hex_encode`).                                 |
| Inbound frame missing                                     | `recv_seconds` too small for the server's latency                       | Increase Recv seconds; re-send.                                                                  |
| Transcript shows `[error] <msg>` as a recv               | Server closed mid-recv                                                  | Working as designed — closed flag is set; check the message.                                     |
| Headers on send-more aren't the same as on connect        | Only URL is reused on send-more                                         | Re-paste headers on the send-more form if you need them.                                         |
| Old transcripts pile up                                   | They're per-project, not auto-pruned                                    | Delete from `/ws/` index; or wipe `project_state` keys via the CLI / SQLite directly.            |

## Test contract

- `reqlore/tests/unit/test_web_smoke_phase4.py::test_ws_index` — list page renders.
- `…::test_ws_new_form` — new-session form renders.
