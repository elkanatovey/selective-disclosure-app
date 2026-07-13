# API Reference

The HTTP API of the Selective Disclosure Report Ledger. This is a **reference**
(request/response shapes, status codes, auth); for *why* the API is shaped this
way — the trust model, redaction invariants, and design rationale — see
[`DESIGN.md`](DESIGN.md) §9. A running node also serves an auto-generated OpenAPI
3.0 document at `GET /app/api`. The exact CBOR request/response shapes are
specified in CDDL (RFC 8610) at [`spec/api.cddl`](../spec/api.cddl) (and the
statement/token format at [`spec/statement.cddl`](../spec/statement.cddl)).

## Conventions

- **Base URL / prefix.** Application endpoints are served under the **`/app`**
  prefix, e.g. `https://<node>/app/reports`. A dev sandbox node listens on
  `https://127.0.0.1:8000`.
- **TLS.** The node presents the service (network) identity certificate; clients
  use it as the TLS root (`workspace/sandbox_common/service_cert.pem` in a
  sandbox).
- **Encoding.** Request and response bodies are **CBOR** (`application/cbor`)
  unless noted. Token artifacts (statements, receipts) are **COSE**
  (`application/cose`). There is no JSON request body anywhere.
- **Transaction id.** Endpoints that commit a transaction return the committed
  id in the standard **`x-ms-ccf-transaction-id`** response header (format
  `<view>.<seqno>`, e.g. `2.15`). It is the handle for every later lookup.
- **Historical reads & retries.** Endpoints that read a committed transaction by
  id (`GET /statements/{txid}`, `.../receipt`, `GET /operator/statements/{txid}`,
  and the disclosure POST) are served from CCF's historical index. While the
  entry is being fetched they return **`202 Accepted`** or **`503`
  (TransactionNotCached)**; the caller should **retry** until the entry
  resolves. Immediately after an async submission (`?wait=false`), a lookup may
  also return **`404`** with body code `TransactionPendingOrUnknown` until the
  transaction globally commits.
- **Errors.** Error responses use CCF's standard JSON body
  (`application/json`): `{"error": {"code": "<Code>", "message": "<text>"}}`,
  with an appropriate 4xx/5xx status. Common codes: `InvalidInput` (400),
  `ResourceNotFound` (404), `InternalError` (500/503).

## Authentication & roles

| Role | CCF policy | Sandbox identity | Used by |
|---|---|---|---|
| **Public** | none | — | submission + all read/verify endpoints |
| **Member** | `member_cert_auth` | `member0_*` | control-plane (signing-key registration/rotation) |
| **Operator** | `user_cert_auth` | `user0_*` | confidential egress (unredacted reads, disclosure, follow-ups) |

The **Operator** is simply a CCF **user** added by governance; this ledger treats
the confidential-egress endpoints as Operator-only. Present the client
certificate for member/Operator endpoints (mutual TLS).

**Caching.** Confidential-egress responses (`GET /operator/statements/{txid}`,
`POST /operator/statements/{txid}/disclosure`, and `GET /operator/statements`)
set **`Cache-Control: no-store`** on every response (success and error) so no
cache retains sensitive plaintext. Public transparency responses are cacheable.

---

## Public endpoints

### `GET /version`
Service-discovery metadata. No auth.

- **200** — CBOR map:
  - `app_version` (tstr) — the ledger app's semantic version.
  - `schema_version` (int) — the statement schema version this build implements.
  - `ccf_version` (tstr) — the underlying CCF platform version.

### `POST /reports`
Submit a report. No auth (open submission — the service is the sole signer).

- **Query:** `wait` (bool, default `true`). `wait=false` returns as soon as the
  transaction commits locally (does not block on global commit).
- **Request body** (`application/cbor`): a **content-fields map** with named
  keys and native CBOR types — see [Report fields](#report-fields). A `parent`
  key is **ignored** here (it is not a submit field; it is server-derived for
  follow-ups).
- **204 No Content** (sync, default) — the statement was built, signed, stored,
  and **globally committed**; the id is in `x-ms-ccf-transaction-id`.
- **202 Accepted** (`wait=false`) — committed locally; the id is in
  `x-ms-ccf-transaction-id`. Poll `GET /statements/{txid}/receipt` for the proof.
- **400** `InvalidInput` — body is not a valid CBOR content map / wrong field type.
- **500** `InternalError` — statement construction/signing failed.
- **503** — issuer key not initialised (`POST /signing-key` first), or the
  transaction was rolled back before global commit.

### `GET /statements/{txid}`
The redacted **transparent statement**: the redacted SD-CWT with its CCF receipt
embedded (COSE unprotected-header label 394). No auth. (Historical read — see
retry note.)

- **200** — `application/cose`. The statement contents stay hidden; existence,
  ordering (seqno), and integrity are provable from the embedded receipt.
- **404** `ResourceNotFound` — `{txid}` did not commit a statement.

### `GET /statements/{txid}/receipt`
The CCF **receipt alone** (`application/cose`) — the inclusion/ordering proof
without the (redacted) statement bytes. Useful as the poll target after an async
submission. No auth. (Historical read — see retry note.)

- **200** — `application/cose` (the COSE receipt).
- **404** `ResourceNotFound` — `{txid}` did not commit a statement.

### `GET /signing-key`
The issuer public key **plus its on-ledger endorsement**, so a verifier can trust
statements signed by this key without each statement's own receipt. No auth.

- **Query:** `at` (int seqno, optional). Default returns the **latest**
  registration; `at={seqno}` returns the registration active at that seqno (the
  greatest registration seqno ≤ `at`), so a statement signed **before** a key
  rotation is verified under the key that signed it.
- **200** — CBOR map:
  - `key` (bstr) — the issuer public key, PEM bytes.
  - `receipt` (bstr) — the COSE receipt of the key's registration transaction,
    whose claims digest is `SHA-256(key)`; verify it against the service identity
    to trust the key.
- **404** `ResourceNotFound` — no issuer key registered at//before the seqno.

---

## Member (control-plane) endpoints

### `POST /signing-key`
Initialise or rotate the issuer signing key. **Member auth** (governance).

- **Query:** `rotate` (bool, default `false`).
- **Request body:** empty.
- Behaviour:
  - First call — generates + registers the issuer key (P-256), endorsing it
    on-ledger (the transaction's claims digest is `SHA-256(pubkey)`).
  - `rotate=true` — registers a **new** key; previous registrations are kept, so
    `GET /signing-key?at=` keeps pre-rotation statements verifiable.
- **204 No Content** — a (new) key was registered and globally committed; id in
  `x-ms-ccf-transaction-id`.
- **200 OK** — idempotent no-op: a key already exists and `rotate` was not set.
- **401 / 403** — caller is not a member.
- **503** — the registration transaction was rolled back before global commit.

---

## Operator (confidential-egress) endpoints

All require **Operator auth** (`user_cert_auth`). Unauthenticated callers get
**401 / 403**.

### `GET /operator/statements/{txid}`
The **fully unredacted** transparent statement — the redacted token with **all**
retained disclosures presented + the receipt embedded. (Historical read — see
retry note.)

- **200** — `application/cose` (unredacted transparent statement). If no
  disclosures were retained, all fields simply stay redacted (still `200`).
- **404** `ResourceNotFound` — `{txid}` is not a statement submission.
- **500** `InternalError` — failed to build the unredacted statement.

### `GET /operator/statements`
Stream the txids of committed statements (reports **and** follow-ups) over a
seqno range, in seqno order.

- **Query:** `from` (int seqno, default `1`), `to` (int seqno, default = current
  indexed watermark; clamped to it).
- **200** — CBOR map:
  - `statements` (array of tstr) — statement txids in `[from, to]`, seqno order.
  - `from`, `to` (int) — the seqno range this page covers (`to` is the highest
    seqno covered; the next poll starts at `to + 1`).
  - `watermark` (int) — the current ledger tip (block count / "caught up"
    signal: once `to == watermark`, the stream is drained).
  - `next` (int, **optional**) — present only when the requested range spans more
    than one page; the `from` to use for the next page.
- **503** — the statement index is not ready for the requested range; retry.
- **500** `InternalError` — failed to resolve a committed seqno to a txid.

The Operator drains the stream by polling `from = to + 1` until `to == watermark`,
then fetches each unredacted statement via `GET /operator/statements/{txid}`.

### `POST /operator/statements/{txid}/disclosure`
Selectively disclose a chosen subset of a stored statement's fields, returning a
presented **transparent statement** the Operator can hand to a researcher.
(Historical read — see retry note.)

- **Request body** (`application/cbor`): `{"fields": [ entry, ... ]}` where each
  `entry` is either:
  - a **field name** (tstr), e.g. `"fingerprint"` — discloses the whole field; or
  - a **path** (array), e.g. `["references", 0]` — discloses a nested array
    element (name followed by index/indices). Required ancestors are attached
    automatically.
- **200** — `application/cose`: the redacted token with only the selected
  disclosures (+ their required ancestors) presented and the receipt embedded.
  Verifiable offline against the issuer key; every non-disclosed field stays
  hidden, including on the wire.
- **400** `InvalidInput` — unknown field name or malformed selection.
- **404** `ResourceNotFound` — `{txid}` is not a statement, or no disclosures
  were retained for it.
- **500** `InternalError` — failed to build the disclosure.

### `POST /reports/{parent_txid}/follow-ups`
Append a follow-up statement cryptographically bound to an existing statement.

- **Query:** `wait` (bool, default `true`) — same semantics as `POST /reports`.
- **Request body** (`application/cbor`): a content-fields map, same shape as
  `POST /reports` (`parent` is server-derived and ignored). The server sets
  `parent = SHA-256({parent_txid}'s token)` = the parent's claims digest, so the
  child commits to exactly the statement the parent's receipt attests.
- **204 No Content** (sync) / **202 Accepted** (`wait=false`) — id in
  `x-ms-ccf-transaction-id`.
- **400** `InvalidInput` — malformed content body.
- **404** `ResourceNotFound` — `{parent_txid}` did not commit a statement.
- **500** `InternalError` — statement construction/signing failed.
- **503** — issuer key not initialised, or the transaction was rolled back
  before global commit.

---

## Report fields

Accepted keys in the `POST /reports` and follow-up content map (all **optional**,
native CBOR types):

| Key | Type | Notes |
|---|---|---|
| `title` | tstr | |
| `body` | tstr | |
| `component` | tstr | |
| `severity` | tstr | |
| `patch` | tstr | |
| `fingerprint` | bstr | byte string (e.g. a hash) |
| `references` | array of tstr | individually disclosable by index |
| `patch_date` | int | |

`parent` is not a submit field — it is server-derived for follow-ups, so a
`parent` key sent to `POST /reports` is ignored. Absent fields are decoy-padded
so every stored statement has an identical
redacted shape (reports and follow-ups are indistinguishable at rest).

## Verifying a statement offline

A statement (transparent or presented) is verified with the `sd_cwt` reference
library against the endorsed issuer key:

```python
from sd_cwt import statement as st
out = st.validate_statement(cose_bytes, issuer_key)   # checks issuer signature +
                                                      # resolves presented disclosures
print(out.disclosed)   # {field_id: value, ...} for the disclosed fields
```

`validate_statement` verifies the **issuer signature** and resolves the presented
disclosures (there is no key-binding token — the service is the sole signer).
Trust in `issuer_key` itself comes from verifying the endorsement receipt returned
by `GET /signing-key` against the service identity. Callers whose trust comes from
the CCF **receipt** instead of the issuer signature can use
`st.validate_statement_trusted(cose_bytes)`. See `test/e2e/test_reports.py` for
worked end-to-end examples.
