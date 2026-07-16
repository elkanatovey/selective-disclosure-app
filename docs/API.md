# API Reference

The HTTP API of the Selective Disclosure Report Ledger. This page is a reference
for request and response shapes, status codes, and auth. For why the API is
shaped this way, including the trust model, redaction invariants, and design
rationale, see [`DESIGN.md`](DESIGN.md) §9. A running node also serves an
auto-generated OpenAPI 3.0 document at `GET /app/api`. The exact CBOR shapes are
specified in CDDL (RFC 8610): the API bodies at [`spec/api.cddl`](../spec/api.cddl)
and the statement and token format at [`spec/statement.cddl`](../spec/statement.cddl).

## Conventions

- **Base URL and prefix.** Application endpoints are served under the `/app`
  prefix, for example `https://<node>/app/reports`. A dev sandbox node listens on
  `https://127.0.0.1:8000`.
- **TLS.** The node presents the service, or network, identity certificate, and
  clients use it as the TLS root. In a sandbox it is
  `workspace/sandbox_common/service_cert.pem`.
- **Encoding.** Request and response bodies use CBOR (`application/cbor`) unless
  noted. Token artifacts such as statements and receipts use COSE
  (`application/cose`). No endpoint takes a JSON request body.
- **Transaction id.** Endpoints that commit a transaction return the committed id
  in the standard `x-ms-ccf-transaction-id` response header, formatted
  `<view>.<seqno>`, for example `2.15`. It is the handle for every later lookup.
- **Historical reads and retries.** Endpoints that read a committed transaction
  by id (`GET /statements/{txid}`, `.../receipt`, `GET /operator/statements/{txid}`,
  and the disclosure POST) are served from CCF's historical index. While the
  entry is being fetched they return `202 Accepted` or `503
  (TransactionNotCached)`, and the caller should retry until the entry resolves.
  Immediately after an async submission (`?wait=false`), a lookup may also return
  `404` with body code `TransactionPendingOrUnknown` until the transaction
  globally commits.
- **Errors.** Error responses use CCF's standard JSON body (`application/json`):
  `{"error": {"code": "<Code>", "message": "<text>"}}`, with an appropriate 4xx
  or 5xx status. Common codes are `InvalidInput` (400), `ResourceNotFound` (404),
  and `InternalError` (500 or 503).

## Authentication and roles

| Role | CCF policy | Sandbox identity | Used by |
|---|---|---|---|
| **Public** | none | — | submission + all read/verify endpoints |
| **Member** | `member_cert_auth` | `member0_*` | control-plane (signing-key registration/rotation) |
| **Operator** | `user_cert_auth` | `user0_*` | confidential egress (unredacted reads, disclosure, follow-ups) |

The Operator is a CCF user added by governance, and this ledger treats the
confidential-egress endpoints as Operator-only. Present the client certificate
for member and Operator endpoints, over mutual TLS.

**Caching.** Confidential-egress responses set `Cache-Control: no-store` on every
response, success and error alike, so no cache retains sensitive plaintext. This
covers `GET /operator/statements/{txid}`, `POST /operator/statements/{txid}/disclosure`,
and `GET /operator/statements`. Public transparency responses are cacheable.

---

## Public endpoints

### `GET /version`
Service-discovery metadata. No auth.

- **200** — CBOR map:
  - `app_version` (tstr) — the ledger app's semantic version.
  - `schema_version` (int) — the statement schema version this build implements.
  - `ccf_version` (tstr) — the underlying CCF platform version.

### `POST /reports`
Submit a report. No auth: submission is open because the service is the sole
signer.

- **Query:** `wait` (bool, default `true`). `wait=false` returns as soon as the
  transaction commits locally and does not block on global commit.
- **Request body** (`application/cbor`): a content-fields map with named keys and
  native CBOR types. See [Report fields](#report-fields). A `parent` key is
  ignored here; it is not a submit field and is server-derived for follow-ups.
- **204 No Content** (sync, default) — the statement was built, signed, stored,
  and globally committed. The id is in `x-ms-ccf-transaction-id`.
- **202 Accepted** (`wait=false`) — committed locally. The id is in
  `x-ms-ccf-transaction-id`; poll `GET /statements/{txid}/receipt` for the proof.
- **400** `InvalidInput` — body is not a valid CBOR content map, or a field has
  the wrong type.
- **500** `InternalError` — statement construction or signing failed.
- **503** — issuer key not initialised (call `POST /signing-key` first), or the
  transaction was rolled back before global commit.

### `GET /statements/{txid}`
The redacted transparent statement: the redacted SD-CWT with its CCF receipt
embedded at COSE unprotected-header label 394. No auth. This is a historical
read; see the retry note.

- **200** — `application/cose`. The statement contents stay hidden, while
  existence, ordering by seqno, and integrity are provable from the embedded
  receipt.
- **404** `ResourceNotFound` — `{txid}` did not commit a statement.

### `GET /statements/{txid}/receipt`
The CCF receipt alone (`application/cose`), which is the inclusion and ordering
proof without the redacted statement bytes. It is a useful poll target after an
async submission. No auth. This is a historical read; see the retry note.

- **200** — `application/cose` (the COSE receipt).
- **404** `ResourceNotFound` — `{txid}` did not commit a statement.

### `GET /signing-key`
The issuer public key plus its on-ledger endorsement, so a verifier can trust
statements signed by this key without each statement's own receipt. No auth.

- **Query:** `at` (int seqno, optional). The default returns the latest
  registration. `at={seqno}` returns the registration active at that seqno,
  meaning the greatest registration seqno ≤ `at`, so a statement signed before a
  key rotation is verified under the key that signed it.
- **200** — CBOR map:
  - `key` (bstr) — the issuer public key, PEM bytes.
  - `receipt` (bstr) — the COSE receipt of the key's registration transaction,
    whose claims digest is `SHA-256(key)`. Verify it against the service identity
    to trust the key.
- **400** `InvalidQueryParameterValue` — `at` was present but not a valid unsigned
  integer. A malformed `at` is rejected rather than silently treated as "latest",
  which would defeat rotation-safety.
- **404** `ResourceNotFound` — no issuer key registered at or before the seqno.

---

## Member (control-plane) endpoints

### `POST /signing-key`
Initialise or rotate the issuer signing key. Member auth (governance).

- **Query:** `rotate` (bool, default `false`).
- **Request body:** empty.
- Behaviour:
  - First call generates and registers the issuer key (P-256) and endorses it
    on-ledger, so the transaction's claims digest is `SHA-256(pubkey)`.
  - `rotate=true` registers a new key. Previous registrations are kept, so
    `GET /signing-key?at=` keeps pre-rotation statements verifiable.
- **204 No Content** — a new key was registered and globally committed. The id is
  in `x-ms-ccf-transaction-id`.
- **200 OK** — idempotent no-op: a key already exists and `rotate` was not set.
- **401 / 403** — caller is not a member.
- **503** — the registration transaction was rolled back before global commit.

---

## Operator (confidential-egress) endpoints

All require Operator auth (`user_cert_auth`). Unauthenticated callers get
**401 / 403**.

### `GET /operator/statements/{txid}`
The fully unredacted transparent statement: the redacted token with all retained
disclosures presented and the receipt embedded. This is a historical read; see
the retry note.

- **200** — `application/cose` (unredacted transparent statement).
- **404** `ResourceNotFound` — `{txid}` is not a statement submission, or no
  confidential disclosures were retained for it, consistent with
  `POST …/disclosure`.
- **500** `InternalError` — failed to build the unredacted statement.

### `GET /operator/statements`
Stream the txids of committed statements, both reports and follow-ups, over a
seqno range in seqno order.

- **Query:** `from` (int seqno, default `1`), `to` (int seqno, default is the
  current indexed watermark and clamped to it).
- **200** — CBOR map:
  - `statements` (array of tstr) — statement txids in `[from, to]`, seqno order.
  - `from`, `to` (int) — the seqno range this page covers. `to` is the highest
    seqno covered, and the next poll starts at `to + 1`.
  - `watermark` (int) — the current ledger tip. It is the block count and the
    "caught up" signal: once `to == watermark`, the stream is drained.
  - `next` (int, optional) — present only when the requested range spans more than
    one page. It is the `from` to use for the next page.
- **400** `InvalidQueryParameterValue` — `from` or `to` was present but not a
  valid unsigned integer. A malformed cursor is rejected rather than silently
  defaulted, which could make an Operator believe the stream was drained.
- **503** — the statement index is not ready for the requested range; retry.
- **500** `InternalError` — failed to resolve a committed seqno to a txid.

The Operator drains the stream by polling `from = to + 1` until `to == watermark`,
then fetches each unredacted statement via `GET /operator/statements/{txid}`.

### `POST /operator/statements/{txid}/disclosure`
Selectively disclose a chosen subset of a stored statement's fields, returning a
presented transparent statement the Operator can hand to a researcher. This is a
historical read; see the retry note.

- **Request body** (`application/cbor`): `{"fields": [ entry, ... ]}` where each
  `entry` is either:
  - a field name (tstr), for example `"fingerprint"`, which discloses the whole
    field; or
  - a path (array), for example `["references", 0]`, which discloses a nested
    array element as a name followed by one or more indices. Required ancestors
    are attached automatically.
- **200** — `application/cose`: the redacted token with only the selected
  disclosures, plus their required ancestors, presented and the receipt embedded.
  It is verifiable offline against the issuer key, and every non-disclosed field
  stays hidden, including on the wire.
- **400** `InvalidInput` — unknown field name or malformed selection.
- **404** `ResourceNotFound` — `{txid}` is not a statement, or no disclosures were
  retained for it.
- **500** `InternalError` — failed to build the disclosure.

### `POST /reports/{parent_txid}/follow-ups`
Append a follow-up statement cryptographically bound to an existing statement.

- **Query:** `wait` (bool, default `true`), with the same semantics as
  `POST /reports`.
- **Request body** (`application/cbor`): a content-fields map, the same shape as
  `POST /reports`, where `parent` is server-derived and ignored. The server sets
  `parent = SHA-256({parent_txid}'s token)`, the parent's claims digest, so the
  child commits to exactly the statement the parent's receipt attests.
- **204 No Content** (sync) / **202 Accepted** (`wait=false`) — id in
  `x-ms-ccf-transaction-id`.
- **400** `InvalidInput` — malformed content body.
- **404** `ResourceNotFound` — `{parent_txid}` did not commit a statement.
- **500** `InternalError` — statement construction or signing failed.
- **503** — issuer key not initialised, or the transaction was rolled back before
  global commit.

---

## Report fields

Accepted keys in the `POST /reports` and follow-up content map. All are optional
and use native CBOR types.

| Key | Type | Notes |
|---|---|---|
| `title` | tstr | |
| `body` | tstr | |
| `component` | tstr | |
| `severity` | tstr | |
| `patch` | tstr | |
| `fingerprint` | bstr | byte string, for example a hash |
| `references` | array of tstr | individually disclosable by index |
| `patch_date` | int | |

`parent` is not a submit field. It is server-derived for follow-ups, so a
`parent` key sent to `POST /reports` is ignored. Absent fields are decoy-padded so
every stored statement has an identical redacted shape, which is what makes
reports and follow-ups indistinguishable at rest.

## Verifying a statement offline

A statement, whether transparent or presented, is verified with the `sd_cwt`
reference library against the endorsed issuer key:

```python
from sd_cwt import statement as st
out = st.validate_statement(cose_bytes, issuer_key)   # checks issuer signature +
                                                      # resolves presented disclosures
print(out.disclosed)   # {field_id: value, ...} for the disclosed fields
```
