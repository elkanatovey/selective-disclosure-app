# Selective Disclosure App — Design & Plan

A confidential, append-only bug-report ledger built on CCF from source. Reports
are registered in a TEE-backed transparency service so their existence and
ordering are provable while their contents stay hidden by default. The Operator
can selectively reveal specific fields to prove a new submission is a duplicate
without exposing the rest.

Status: design agreed; implementation starts from the in-repo `basic` sample
at `app/src/app.cpp`, currently a plain key/value store.

---

## 1. Goal / use case
- Registration is provable and tamper-evident via monotonic seqno ordering.
- Report contents are hidden by default.
- The Operator can selectively disclose chosen fields to a researcher to provide evidence of a
  duplicate, revealing nothing else.

A statement is a multi-field object. The content fields are `title`, `body`,
`component`, `severity`, `fingerprint`, `references`, `patch`, and
`patch_date`. All are selectively-disclosable. A `parent` reference links
follow-ups to a report. Follow-up notes are optional and added later.

### Terminology: report vs note
A report and a note/follow-up are the same kind of object: an SD-CWT statement
with fields and the always-full `parent`. They differ only by role:
- report = a *root* statement. It is the original submission, typically by a
  researcher; `parent` = none/garbage.
- note / follow-up = a *child* statement. It is generally a later addition by the
  Operator containing component/severity, patch, or detail; `parent` = a real
  report.


### Statement schema (RESOLVED — todo: define-report-fields)
One unified statement schema; `report` and `note` share it, with role derived
purely from `parent`. There is deliberately no `statement_type` field, because a
visible type would itself leak *whether* a parent exists and so defeat the
redacted-`parent` design.

**Signing:** the service constructs and signs every
statement in-enclave *before* consensus; the committed seqno is the
authoritative order/time. The clear `iss` is therefore the service, not the
submitter.

| Key | Claim | Visibility | Notes |
|---|---|---|---|
| `170` (hdr) | `sd_alg` | clear (machinery) | SHA-256; the only structurally-clear item |
| `1` | `iss` | **clear** | service identity (constant across all statements) |
| `6` | `iat` | **clear** | service sign-time (pre-consensus wall-clock) |
| `1000` | `parent` | **SD, always present** | parent-statement hash; garbage sentinel when root |
| `1001` | `title` | SD | short summary |
| `1002` | `body` | SD | full report text |
| `1003` | `component` | SD | affected component/product |
| `1004` | `severity` | SD | severity rating |
| `1005` | `fingerprint` | SD | normalized dedup key — the field disclosed to prove duplicates |
| `1006` | `references` | SD | array (CVEs/URLs), redacted **whole** (not per-element) |
| `1007` | `patch` | SD | patch id/description (Operator follow-ups) |
| `1008` | `patch_date` | SD | when patched |

**Strict uniformity:** every statement always carries all 9 content fields as
redacted entries. Absent fields are padded with a random garbage sentinel,
exactly as `parent` is when root. A bare redacted token therefore always exposes
exactly `iss` + `iat` + `sd_alg` + 9 Redacted Claim Hashes. A one-line note and
a full report look identical, leaking neither field presence, size, nor the
report-vs-note distinction. `references` is redacted as a whole claim, not
tag-60 per-element, precisely to preserve this uniform shape.

Report-vs-note is decided only by disclosing `parent`: a real, on-ledger
hash ⇒ note; a garbage sentinel ⇒ root. Undisclosed, the two are
indistinguishable. `iat` is kept clear for now. That is standard and creates a
minor timing leak; it could be redacted later for maximum uniformity without
touching the token core.

Implemented in `tools/sd_cwt/statement.py` for schema/oracle and
researcher-side verification. Tested in
`tools/sd_cwt/tests/test_statement.py`.

## 2. Report structure
- Multi-field object; all content fields are selectively-disclosable, and
  one field is `parent` for linkage.
- **Strict uniformity.** Every content field is always present and constant-shape:
  each content field is included and redacted, padded with a random garbage
  sentinel when it has no real value. `parent` when there is no real parent is
  just the special case of this general rule.
- Content fields, including `parent`, are redacted by default. In a
  stored/redacted token they appear only as Redacted Claim Hashes, leaking
  nothing: not even *whether* a parent exists, nor how many fields are set. The
  Operator discloses a field only when it wants to prove it.
- **Principle: a redacted token must leak no metadata.** The token *shape* means
  which claims appear and the count of redacted entries. It should be uniform
  across statements regardless of content, so the pattern itself reveals nothing.

## 3. Roles & trust model
| Role | Who | Notes |
|---|---|---|
| Reporter (originals) | **Researchers** | submit **raw report content** directly to the service (authenticated channel) |
| Follow-ups | **the Operator** | submits follow-up note content referencing a report |
| Notary / Transparency service | **CCF service in a TEE** | **constructs + signs** the SD-CWT, registers it, assigns **seqno**, issues **signed receipts**, holds the confidential store; trust domain **separate** from the Operator |
| Holder of disclosures | **the service** (current behavior) — or **Operator self-custody** (deferred, §12) | only the holder of salt/value can disclose |
| Verifier | a **researcher** | verifies **offline** via the receipt (`validate_trusted`) |

**Core flow:** reports go researcher → service → the Operator, never the
Operator → service. This blocks Operator front-running, because the Operator
only sees a report after the service has already assigned a seqno. The Operator
enriches the record afterward via follow-ups to make later duplicate-proofs
easier.

## 4. Authentication / registration model (notary)
The service is a notary + signer, not an identity authority.
- **The service is the sole signer.** Researchers/Operator submit raw
  content over an authenticated channel; the service constructs and signs the
  SD-CWT. There is no per-submitter statement signature to check.
- **Signing key = app-managed, not the CCF service identity.** CCF does not
  expose the service identity private key to app code; it signs receipts
  internally. The app therefore holds its own EC P-256 issuer key in a private,
  encrypted, replicated KV table. The key is lazily generated on first use so any
  primary can sign. Two independent, service-rooted anchors result: the
  statement signature uses the app key and binds the Redacted Claim Hashes, while
  the receipt uses the CCF service identity and proves inclusion + seqno.
- **The issuer key is service-identity-endorsed via the ledger.** On generation
  the issuer public key is written to a public KV history table; that
  registration transaction gets a receipt signed by the CCF service identity,
  which *is* the endorsement. It uses the same trust root as statement receipts,
  with no bespoke cert-signing, which the app could not do anyway.
  `GET /signing-key` returns the public key plus its endorsement receipt, so a
  verifier trusts the issuer key by checking it against the service identity, not
  by trusting the endpoint. This makes the app key follow the service-key trust
  logic.
- **Key rotation follows the service-key pattern.** Rotating the issuer key is a
  governance-audited action that registers a new public key and new receipt, and
  retains the old ones in the history table, so statements signed under a
  previous key stay verifiable against their still-endorsed key. This mirrors
  CCF's service-identity endorsement chain and inherits service-identity rotation
  across recovery for free through the receipts. See §12.
- **No key enrollment.** Submitter identity is not a CCF user set; the receipt
  proves "this statement existed at seqno T", signed by the service.
- Verification is receipt-anchored through `validate_trusted`: a verifier trusts
  the statement because of the service signature + receipt, not by re-checking a
  submitter's key. Submitter authorship "beyond that doesn't matter" for the
  core flow.
- Submitter authentication is a transport/channel concern: who may submit. It is
  orthogonal to the statement signature; optional anti-spam such as
  rate-limit/JWT sits here.
- Operator authorization is mandatory for confidential-egress endpoints
  `get_statements`, `get_statement`, and `make_disclosure`; see §9. These
  endpoints return plaintext, so they are gated to a config-pinned or
  governance-set Operator identity. This is the one place caller authentication
  is required; submission itself needs none.

## 5. Threat model
**Defended:**
- Operator front-running researchers: direct researcher→service submission
  anchors precedence by seqno before the Operator sees the report.
- Operator backdating / fabricating precedence: TEE-signed receipt + monotonic
  seqno; a fabricated "earlier" statement can only get a *current* seqno.
- Log tampering: append-only Merkle ledger, service-signed.
- Over-disclosure: selective disclosure reveals only matching fields;
  the rest remain salted hashes.
- Content exposure to auditors / replicas: public ledger entry holds only
  the redacted/committed form.
- Disclosure forgery: `hash ∈ signed payload` + collision resistance.
- Statement-signature forgery: the service in the TEE signs; verifiers check
  against the service cert / attestation-rooted key.
- Linkage / metadata leakage: `parent` is always-present AND redacted;
  uniform token shape leaks no metadata, not even whether a parent exists.

**Assumptions / trusted:** TEE attestation holds, so only attested code wields
the service key or sees confidential state. Its strength is
deployment-dependent. Issuer keys are secure; verifiers hold Operator pubkey +
service cert/endorsements as out-of-band trust anchors; salts are high-entropy.

## 6. Cryptographic building blocks
- COSE_Sign1: researcher/Operator-signed statements; verifying key may ride in
  the statement.
- SD-CWT, draft-ietf-spice-sd-cwt-08: salted-hash redaction. Disclosable fields
  become Redacted Claim Hashes in the signed payload, using
  `redacted_claim_keys = simple(59)` for map entries and tag `60` for array
  elements. `[salt, value, key]` disclosures live in the unprotected header,
  `sd_claims` label 17. Reveal by hash-match; redact by dropping disclosures.
  The signature is unaffected.
- CCF receipt: service-signed inclusion proof binding the claims digest;
  offline-verifiable with the service cert.
- SHA-256 + CBOR.
- Present in the built CCF and called directly: COSE verify through
  `ccf::crypto::cose_verifier`, `ccf::cose::edit::set_unprotected_header`,
  receipt APIs `describe_merkle_proof_v1`, `describe_cose_signature_v1`, and
  `build_receipt_for_committed_tx`, SHA-256 through `ccf::crypto::sha256`, EC
  signing through `ccf::crypto::ECKeyPair::sign_hash`, and CSPRNG through
  `ccf::crypto::get_entropy()`.
- COSE_Sign1 _creation_ is NOT exposed by CCF. Public `cose.h` only edits
  headers. Since the service is the sole signer, we hand-assemble the
  `COSE_Sign1` with QCBOR and sign the `Sig_structure` via `ccf::crypto`; no
  `t_cose` dependency.
- CBOR encode/decode is NOT exposed by CCF for general use, so we vendor
  QCBOR via CMake `FetchContent` to build/parse token bytes.
- CCF-source modification is last resort.

## 7. The disclosure artifact
Prefer option (b), the separate standard bundle: hand the verifier three standard
objects `{ SD-CWT, receipt, disclosures }`. Nothing non-standard; the verifier
runs three standard checks: COSE sig-check, SD-CWT hash-match, and receipt-check.

Alternative option (a), embedded: receipt + selected disclosures are placed in
the SD-CWT's unprotected header, producing one self-contained COSE_Sign1. It is a
standard COSE object carrying a standard *combination* of SD-CWT + transparency
receipt. No single spec names the combo, so no off-the-shelf tool validates it as
one unit.

```
COSE_Sign1 (service-signed, TEE):
  protected   : { alg, typ, sd_alg(SHA-256) }
  payload     : { clear fields,
                  redacted_claim_keys:[hashes incl. always-present parent] }
  unprotected : { receipt: <service-signed>,        # (a) only
                  sd_claims:[selected disclosures] } # (a) only
```

The exact wire format is specified in CDDL, RFC 8610, at
[`spec/statement.cddl`](../spec/statement.cddl). It is the language-neutral
contract both the C++ token core and the Python `sd_cwt` oracle conform to.
Protected header keys are emitted in CDE order: `alg` (1) < `typ` (16) <
`sd_alg` (170).

## 8. Data model (KV tables)
Statements/disclosures are written as per-transaction `Value`s and read back
by historical query at the txid's seqno. They are not stored in a map keyed by
id. A seqno index enables the Operator stream. Concrete names are in
`app/src/reports.h`.

| Table | Visibility | Contents |
|---|---|---|
| `StatementTable` (`public:sd.statement`) | public | the redacted SD-CWT bytes (per-tx `Value`) |
| `DisclosureTable` | private (encrypted) | the statement's disclosures (`[salt,value,key]` bytes) — the **confidential store**; **write-only** from submit, **read-only** from Operator egress. Always retained today; an Operator-self-custody mode (`store_unredacted` OFF) is deferred (§12) |
| `SigningKeyTable` (`sd.signing_key`) | private (encrypted) | the issuer **private** key (PEM) |
| `SigningKeyHistory` | public | issuer **public** key registration(s) — endorsed by their receipts (§4); supports rotation (append new, keep old) |
| statement **seqno index** | public | for `get_statements` (CCF `SeqnosForValue`) |

No parent→children index: we deliberately do not maintain a parent-to-follow-ups
mapping. Such an index would leak thread structure, because parent hashes are
derivable from the public tokens. It is also not needed: the link lives in the
child's redacted, salted `parent` field, and follow-ups surface via
`get_statements`.

- **Signing:** the service in the TEE constructs and signs the SD-CWT, with
  trust roots in attestation. Researchers submit raw content over an
  authenticated channel.
  The receipt-anchored `validate_trusted` is the verification path.
- Confidential store, retained by default while `store_unredacted` OFF is
  deferred to §12: the service holds the report's disclosures. These are the
  unredacted values for redacted fields; with the public token's clear fields,
  they reconstruct the full report. This choice keeps the first implementation
  simple, dissolves the separate confidential-delivery channel, and lets the
  service produce duplicate-proofs directly.
- **Granular + recursive disclosure, implemented:** the store keeps individual
  disclosures, NOT a monolithic plaintext blob, so
  `make_disclosure` can reveal an arbitrary subset at any depth. Because
  nested disclosure follows the ancestor-disclosure rule, each disclosure is
  annotated with its full path, `sdcwt::Disclosure::path`, recorded at issue
  time and persisted in the store as `[path, encoded]`. The disclosure request
  selects the requested targets, their ancestor disclosures so a nested reveal is
  resolvable, and their descendants so disclosing a whole field reveals its
  contents. This is `select_disclosures`. Statements redact each `references`
  element individually with path `{1006, i}`, so the Operator can disclose a single
  reference (`["references", i]`) revealing only its value, not its siblings'
  values. The top-level redacted shape is unchanged: the whole array is still one
  Redacted Claim Hash at rest; element hashes live inside it and appear only
  once the array itself is disclosed.
- **Known limitation: array disclosure leaks length/position.** This is accepted.
  Disclosing an array element necessarily discloses its container, by the
  ancestor rule, and the container carries one `tag(60)` placeholder per element, so
  the disclosed artifact reveals the array's length and lets the recipient
  match the opening to its position. Only sibling *values* stay hidden. This is a
  disclosure-time, recipient-only leak. Nothing leaks at rest; the `public:`
  token still shows just one hash. The recipient is the party we chose to hand a
  duplicate-proof. We deliberately do not hide it, because
  the value is asymmetric: top-level field-presence uniformity defends against
  *every* observer of the world-readable ledger permanently, whereas array count
  reaches only the disclosure recipient. If a future threat model needs it, the
  fix is small and local: pad each redactable array to a fixed cap with salt-only
  decoy element disclosures at issue, mirroring the existing top-level
  `pad_to`, so a disclosed array always shows `MAX_REFS` slots and the real
  count/position is hidden among decoys. The cost is an arbitrary cap and
  larger disclosed artifacts.
- **Segregation invariant, for easy migration:** the redacted-token build,
  claims-digest binding, receipt issuance and the public store never read
  the confidential store. It is *write-only* from the submit path and *read-only*
  from `make_disclosure`. Turning `store_unredacted` OFF is then a one-site
  change: disclosures move to Operator self-custody (§9). An encrypt-to-Operator
  variant would only change this table's value format.
- **Immutability caveat:** the CCF ledger is append-only, so entries written
  while the flag is ON retain their encrypted disclosures permanently. The flag
  controls future writes, not past ones. Migration affects new entries only.
- **Salts are random, per field, using CSPRNG.** This is the production choice. Each
  disclosure carries an independent 128-bit random salt, matching what `sd_cwt`
  already does. The only benefit of *deterministic* salts using
  `salt = HMAC(K_salt, id‖path)` is not having to store salts. Since the service
  stores the confidential data anyway, that benefit is moot here. Deterministic
  salts would also require a sealed single-purpose `K_salt`, never the signing
  key, a strict canonical-encoding requirement, and a real leak surface:
  hash-equality reveals input-equality, so cross-report values must be blinded by
  binding a unique id + full path. Random salts blind every occurrence
  independently, add no key management, and are the least-surprise, spec-aligned
  default. Since a disclosure *is* `(salt,value,key)`, "store the disclosures"
  already stores the salts. No change to `issue()`.
  Deferred option: deterministic salts, only if a future model deliberately
  minimises stored confidential state, stores just the redacted token + `K_salt`,
  reconstructs the disclosures, and uses strict id+path binding.
- Follow-ups reference parent by hash, the always-full field; ordering /
  precedence by seqno.

## 9. Endpoints & off-chain tooling
Locked API contract. The full reference is [`API.md`](API.md). Formats: CBOR in;
responses are COSE for statements/receipts or CBOR for `/version`,
`/signing-key`, and the Operator stream, with `204`/`202` carrying no body. Live
means built in PR #4; pending means format/endpoint changes are agreed but not
yet coded.

**Public, no auth:**
- `GET /version`: service-discovery metadata, CBOR
  `{app_version, schema_version, ccf_version}`. It returns this app's semantic
  version, the compile-time statement schema version so a client knows which
  schema a live service speaks, see §12.1, and the underlying CCF platform
  version. Live.
- `POST /reports[?wait=false]`: CBOR body with a content-fields map:
  `title`/`body`/`component`/`severity`/`fingerprint` bstr/`references`/`patch`/
  `patch_date`; named keys, native types, no `parent`. Builds + signs the
  strict-uniformity SD-CWT, stores the redacted token and its disclosures in the
  confidential store, and binds the claims digest. Synchronous by default: holds
  the response until
  global commit, then 204 + the transaction-id header
  (`x-ms-ccf-transaction-id`). `?wait=false` returns 202 + txid header
  immediately after local commit. The caller polls
  `GET /statements/{txid}/receipt`; this async submit/poll pattern reuses the
  historical receipt endpoint as the poll target, with no separate operations
  resource. Live.
- `GET /statements/{txid}`: the redacted statement with its CCF receipt embedded,
  also called a transparent statement, `application/cose`. Live.
- `GET /statements/{txid}/receipt`: the CCF receipt alone,
  `application/cose`, for a verifier that only needs the inclusion/ordering
  proof, not the redacted statement bytes. Live.
- `GET /signing-key[?at={seqno}]`: the issuer public key plus its endorsement,
  the receipt of its on-ledger registration, so verifiers validate it against the
  service identity (§4). Default returns the latest registration; `?at=` returns
  the registration active at a given seqno, the greatest registration seqno ≤
  `at`, so a statement signed before a rotation is verified under the key that
  signed it. Live.
- `POST /signing-key[?rotate=true]`: member-gated control-plane endpoint, see
  §12. Idempotent init by default; no-op → 200 if already initialised.
  `?rotate=true` registers a new key and returns 204. Old registrations are kept,
  each endorsed by its own receipt, so the `?at=` resolution above keeps
  pre-rotation statements verifiable. Live.

Operator-gated: the caller is the Operator CCF user, `user_cert_auth`, added by
governance as described in §12.2.
- `POST /reports/{parent_txid}/follow-ups`: CBOR content body with the same shape
  as `/reports`. Child statement; `parent` = SHA-256 of `{parent_txid}`'s token
  = the parent's claims digest, so the child commits to exactly the statement
  the parent's receipt attests; server-derived and salted+redacted like any
  field. Uses a read-write historical adapter to read the parent at
  `{parent_txid}` and write the child in one tx; rejects with 404 unless
  `{parent_txid}` genuinely committed a statement. The parent tx's claims digest
  must equal `hash(token read)`, which guards against a stale per-tx `Value` read.
  Returns 204 + txid header, or 202 with `?wait=false`; see [`API.md`](API.md)
  for the full status set. Live. There is no parent→children index; see §8. The
  link lives in the child's redacted, salted `parent` field and follow-ups
  surface via `get_statements`.
- `GET /operator/statements/{txid}`: a single unredacted transparent
  statement: the redacted token with all stored disclosures presented +
  receipt embedded, using `present_transparent` with the full disclosure set.
  Live. Caveat: uniform padding means absent content fields present as garbage
  sentinels. String fields are distinguishable by CBOR type, `bstr` fields are
  not; the Operator relies on out-of-band knowledge of which fields are real.
- `GET /operator/statements?from={seqno}&to={seqno}`: the stream. Returns the
  txids of statements, reports and follow-ups, committed in the seqno range
  `[from, to]`. The default is `from=1`, `to`=current watermark. Results are in
  seqno order, plus the ledger `watermark`, the Operator's block count / "caught
  up" signal, and, when the requested range spans more than one page, a `next`
  cursor, CBOR `{statements:[txid…], from, to, watermark, next?}`. A page covers
  a bounded seqno range. `kMaxSeqnoPerPage` is kept below the index's
  `max_requestable_range`, so a single index query can never exceed that bound.
  There is no server-side windowing. The Operator drains the stream by polling
  `from = to + 1` until `to == watermark`; stateless + replay-idempotent. Uses
  the statement seqno index (`SeqnosForValue_Bucketed<StatementTable>`); the
  Operator then pulls each unredacted statement via `GET /operator/statements/{txid}`.
  Live. Seqno-range pagination caps each page's range below the bound, which
  eliminates the large-ledger windowing path entirely. The tradeoff is that pages
  may be empty over sparse ranges.
- `POST /operator/statements/{txid}/disclosure`: body `{fields:[ entry, ... ]}`.
  Each entry is a field name for a whole field or a path `[name, idx, ...]` for a
  nested array element, for example `["references", 0]`. Returns a single
  presented + transparent COSE artifact with targeted disclosures and their
  required ancestors attached, and with the receipt embedded, for the Operator to
  hand a researcher. `make_disclosure`. Live, including subfield/recursive
  disclosure. Reverts to offline Operator-side tooling if `store_unredacted` is
  OFF, using self-custody.

**Trust/ordering note:** precedence and duplicate ordering use the seqno
anchored by the receipt and trusted. The `iat` clear claim is untrusted host
wall-clock, a convenience timestamp only, never a precedence anchor.

**Confidential-egress authorization:** `get_statements`, `get_statement`,
and `make_disclosure` return confidential plaintext and MUST be gated to the
Operator by a config-pinned / governance-set identity. This is distinct from the
notary/no-enrollment stance for submission (§4). These responses also set
`Cache-Control: no-store` on both success and error paths, so no client,
proxy, or diagnostic cache retains the plaintext. This is defence-in-depth over
the TLS/mTLS that already protects transit. Infrastructure must likewise avoid
logging COSE bodies; the app itself never logs response bodies.

**Off-chain, NOT a service endpoint:**
- `verify`: researcher-side. `validate` checks the issuer signature;
  `validate_trusted` instead assumes trust from an external CCF receipt and does
  not re-check the signature. Both then hash-match the presented disclosures.

**Duplicate proof:** The Operator runs `make_disclosure` on the earlier matching
statement; verifier checks seqno M < their seqno N and that the disclosed
field matches their bug.

## 10. Phased build order (from today's `basic` app)
Build the off-chain token layer first, then the on-chain service on top.
Token creation with CBOR/COSE/SD-CWT is a prerequisite layer; receipts and seqno
are chain logic that *consumes* those tokens.

0. Define the statement schema ✔ for todo: define-report-fields. It covers
   unified report/note fields, clear vs SD per field, redacted-always-present
   `parent`, strict uniformity. Done (§1; `sd_cwt.statement`).
1. Off-chain token layer, Python, ✔ DONE. `sd_cwt` + `sd_cwt.statement`
   already build / sign / redact / present / verify / validate schema-valid
   tokens off-chain, with 73 tests. Since the service is the sole signer, this
   Python layer is the
   reference/conformance oracle and the researcher-side verifier, not
   the in-enclave signer.
2. C++ token core, the port of build+sign+redaction. Host build, no chain.
   Reimplement the authoritative construction in C++ so the service in the TEE can
   sign in-enclave: build the CBOR claims set, garbage-pad to strict uniformity,
   CSPRNG salts, `sd_alg` redaction (`redacted_claim_keys`), and hand-assemble a
   `COSE_Sign1` signed via `ccf::crypto`. No `t_cose`: encode the
   `Sig_structure` with QCBOR, hash, `ECKeyPair::sign_hash`, assemble the
   array. Algorithm-agile like the Python lib: the COSE signing algorithm
   ES256/384/512 is derived from the key's curve, and the redaction hash
   SHA-256/384/512, default SHA-256, is a parameter written to `sd_alg`. Maps
   are emitted in deterministic CDE, RFC 8949 §4.2.1 bytewise, key order on both
   sides. The Python reference canonicalises its emitted CBOR to match; see §14.
   Deterministic encoding is not an SD-CWT wire-format MUST. Only definite-length
   is, draft-08 §5.1. It is the spec's recommended privacy profiling choice
   (§15.2/§16.7) and closes the issuer covert channel from map-key ordering,
   which matters here because the TEE is the issuer. Built as a standalone
   host/virtual test target with no enclave and no chain, then gated by
   cross-impl conformance against the Python oracle: Python
   `validate`s C++ tokens across both ES256/SHA-256 and ES384/SHA-384 suites, and
   with injected fixed salts the C++ protected header and payload are
   byte-identical to Python `issue()`. The ECDSA signature is randomised, so it
   is validated, not byte-compared. Vendor QCBOR via `FetchContent`.
3. On-chain: submit + receipt. `submit_report` constructs+signs via the
   C++ token core, stores the redacted blob, binds the claims digest, returns
   seqno + receipt. Receipt/seqno are chain logic layered on top of 1–2.
4. Follow-ups & linkage. `append_follow_up`, redacted+salted `parent`,
   no parent→children index, seqno ordering.
5. Disclosure & duplicate proof. Operator `make_disclosure` + researcher
   `verify`; end-to-end demo.
6. Optional hardening. `store_unredacted` OFF with Operator self-custody or
   encrypt-to-Operator; redact linkage; config-pinned issuer authorization;
   anti-spam controls; KBT for external subjects. KBT is already implemented in
   the `sd_cwt` lib; wiring into the app is what remains.

## 11. Caveats / open decisions
- Disclosure artifact: separate-bundle, preferred, vs embedded profile.
- RESOLVED: `parent` is redacted by default + always present, with no metadata
  leak.
- RESOLVED for now: the service in the TEE signs statements; the service holds
  the unredacted disclosures in a private table. They are always retained today;
  `store_unredacted` OFF is deferred. The table is segregated for easy migration.
  This dissolves
  the confidential service→Operator delivery channel for the initial
  implementation.
- Principle: redacted tokens leak no metadata; keep token shape uniform.
- ACCEPTED limitation: disclosing an array element reveals the array's
  length/position to the disclosure recipient, never at rest. It is not padded;
  see §8 for the rationale and the small decoy-padding fix if ever needed.
- "Operator can't read confidential state" is deployment/attestation-dependent
  and now load-bearing for whole reports, not just disclosures, since the
  service holds plaintext in an encrypted private table.
- Each layer is standard; only the embedded *combination* is non-standard.

## 12. Governance & versioning
Even with a single entity operating the ledger, governance is not optional. CCF
always runs under a constitution + ≥1 member, and the point of a
transparency service is that *rule changes are themselves recorded on the
append-only ledger*, so the operator cannot silently change behaviour. We split
governance into two planes and deliberately keep only one of them:

- **Data-plane governance, NOT used.** *Who-may-submit* control: accepted
  issuers, trust anchors, a registration policy engine. Our
  notary / sole-signer stance removes the need for this entirely: submission is
  open, the service is the sole signer, and §4 describes the model. We implement
  no submission-gating policy or data-plane governance endpoints. See the note
  below for when it might be reconsidered. It is out of scope for the current PR.
- **Control-plane governance, used.** *Changing the rules*: app/code upgrades,
  schema/format changes, config including the Operator identity, signing-key
  rotation, and service lifecycle / recovery. This is mostly CCF's built-in
  governance; we add only a small amount of custom config.

**Note: a programmable submission policy, JS/Rego, deferred.** A transparency
service can embed a policy engine such as a `ccf::js` JavaScript context or a
Rego/OPA interpreter configured via governance. The engine would run on every
submission to decide whether it is accepted. Such engines exist to police
adversarial issuers/claims in services where submitters sign their own
statements. We structurally do not have that driver: the service signs,
submitters send raw content, and there is no submitted signature/identity to
gate. Even the plausible uses for us, such as evolvable field validation, an
enrolment allow-list, or bug-bounty scope, are governance-managed data. A C++
handler can read that data from a KV config table; it needs no interpreter. An
embedded JS/Rego engine only earns its keep for governance-managed logic we
cannot anticipate in code. Realistically, that arises only if the ledger becomes
multi-tenant / consortium-operated or grows enrolled submission with complex,
frequently-changing eligibility rules. The cost is not CPU. A simple policy is
sub-ms, dwarfed by the consensus round a submission already pays. The cost is
trust surface and operations: an interpreter on the untrusted-input path inside
the TEE, which adds attack surface and a larger attested code measurement; a
tail-latency/DoS vector that must be bounded with heap and time caps plus a max
input size; and the overhead of authoring/testing/governing policies.
Recommendation if the need lands: prefer authenticated submission + a
governance-managed allow-list KV table validated in C++ over an embedded engine,
and only adopt the engine for the genuinely-multi-stakeholder case. Not part of
this PR.

What CCF's built-in governance already covers: member proposals, recorded
on-ledger and auditable.
- Open service, add/remove members & users, disaster recovery.
- Code upgrade: a new app binary is a new code measurement; nodes
  running it are trusted only once governance accepts that measurement. Because
  our schema is compile-time (`statement.h`: field IDs 1000–1008,
  `CONTENT_FIELD_COUNT`, default `sd_alg`), a schema change *is* a code
  upgrade and inherits this audited path.
- Node certs, JWT issuers, and other CCF-native config.

Custom governance-set config we add: a small KV surface, member-writable.
- Operator identity for the confidential-egress endpoints (§4/§9). See the
  A/B decision below.
- Optional: a schema-version pin if we ever want the current version to be
  runtime-configurable rather than purely code-bound.

Issuer-key rotation, control-plane, §4: the app issuer key is registered
on-ledger. Its public key is in a history table, endorsed by its registration
receipt.
Rotation is a governance-audited action that appends a new registered key and
keeps the old ones, so statements under a prior key stay verifiable. This is the
app-key analogue of CCF's service-identity endorsement chain. Recovery is handled
by CCF for the receipt side; the issuer key is KV data that survives recovery.

**Disaster recovery: CCF-native, tested end-to-end at `test/e2e/test_recovery.py`.**
Recovery adds no app code: `sandbox.sh --recover` drives CCF's
`governance.recover_service` from the members' recovery shares, replays the
persisted ledger onto a new service identity, with `recovery_count` bumps and
service cert rolls, and preserves the previous identity on disk
at `predecessor_service_cert.pem`. The e2e test submits a report, tears the service
down, recovers it, and asserts two things. First, the pre-recovery statement is
still retrievable and its original receipt still verifies against the predecessor
identity CCF preserved. Second, the recovered service keeps operating: a new
report commits and its receipt verifies against the new identity. The issuer
signing key is replayed KV data and survives with no re-init. Recovery needs
no app code: the recovery mechanism, the ledger persistence, and the preserved
identity chain are all CCF's. A verifier holding a pre-recovery receipt validates
it against the predecessor cert, the same old key that recovery writes to disk.
We deliberately expose no historical service-key endpoint. The one thing we do
not implement is embedding CCF's `service_endorsements` chain in the receipt so
the current identity alone verifies old receipts. CCF's
`populate_cose_service_endorsements` exists for this, but the Python
`ccf.cose.verify_receipt` takes a single key with no chain support, so it would
need a chain-following verifier too. Deferred; not needed for the model.

### 12.1 Schema / statement versioning
A verifier must know *which schema* a statement used in order to interpret its
fields, and that binding must survive receipts and format changes. Approach:
- **Explicit version claim.** Every statement carries a clear schema/profile
  version. It is a fixed CWT-style claim, present in *all* statements. It is a
  *clear* claim, so it does not affect the redacted-uniformity invariant. That
  invariant is over the redacted content fields, §1. Self-describing and cheap.
  The service-level `SCHEMA_VERSION` is Live and surfaced by `GET /version`;
  embedding it as a per-statement clear claim is the remaining step, deferred.
- **Authoritative binding = code measurement.** The version claim is a
  convenience label; the *authoritative* statement of "what schema/behaviour
  produced this" is the app code measurement, which is governance-audited and
  on-ledger. A verifier can map measurement → schema version if it wants to
  distrust a self-asserted label.
- **Migration is forward-only.** The ledger is append-only: statements keep the
  version they were signed under. A schema upgrade with a governance-accepted new
  measurement affects new statements only; verifiers must retain the ability to
  validate historical versions.

### 12.2 Open decision — Operator identity mechanism
The egress gate, §4/§9, is the one authorization we must pin. Two options:
- A. Config-pinned: Operator cert set in node/app config at deploy; the app
  checks the caller against it. Simplest, zero governance surface, but rotation =
  reconfigure/redeploy. It is not independently recorded as a governance action.
- B. Governance-set: a governance proposal writes the Operator cert into a
  KV table; a custom auth policy reads it. Rotatable, member-approved, and
  auditable on-ledger, consistent with the control-plane philosophy above.
- **Lean:** start with A to unblock the egress endpoints for single-operator
  dev, but B is the principled target. A security-critical authorization
  change *should* be an auditable governance action, not a silent config edit.
  The switch is localized to where the auth policy reads the Operator cert.

## 13. Implementation: reuse map & layering
**Two layers, built in order:**
1. **Off-chain token layer, build first:** create + sign + redact + verify the
   COSE_Sign1 / SD-CWT tokens. Pure client-side crypto using CBOR + COSE +
   SHA-256, no chain, with fast unit-test iteration.
2. **On-chain service layer, on top:** registration, seqno, receipts,
   storage: chain logic that *consumes* tokens from layer 1. Token creation is
   therefore a prerequisite to receipt generation.

**Reuse from CCF:** call these directly; they are already installed.
- `ccf::cose::edit::set_unprotected_header` (+ `desc::Value/Empty`, `pos::AtKey`)
- receipt APIs: `describe_merkle_proof_v1`, `describe_cose_signature_v1`,
  `build_receipt_for_committed_tx`
- COSE verify, SHA-256, KV (`Map`/`Value`/`RawCopySerialisedValue`), seqno indexing.

Patterns we reimplemented as original MIT code: studied for approach, not
copied. The `app/` sources are our own, MIT.
- QCBOR helpers (`app/src/cbor.h`, an app-wide shared util) and COSE_Sign1
  decode / header + COSE_Key parse (`app/src/token/cose.h`), with the TSS/DID
  bits omitted
- CCF-receipt → COSE-receipt conversion (`make_cose_receipt`)
- the register / local-commit flow → template for `submit_report`
- `historical_queries_adapter.h` + CCF `SeqnosForValue` indexing → seqno lookup
- the QCBOR `FetchContent` block in `app/CMakeLists.txt`

**Deliberately not adopted:** did:x509 / JWKS verification, replaced by a
~50-line self-contained verifier; a registration policy engine; data-plane
governance endpoints.

**New code:** the novel parts.
- `sd_cwt` Python library: redaction core with salts, disclosures, Redacted
  Claim Hashes, `redacted_claim_keys` / tag 60, and a `statement.py` schema layer.
  Since the service is the sole signer, authoritative statement
  construction is reimplemented in the C++ enclave; the Python library is
  the reference oracle for that C++ code and the researcher-side offline
  verifier. See §14.
- C++ token core (`app/src/token/`: `cbor_value`, `cose`, `sd_cwt`,
  `statement`): the in-enclave authoritative construction. Hand-assembles a
  `COSE_Sign1` with QCBOR and signs the `Sig_structure` via `ccf::crypto`; no
  `t_cose`. Built as a host `unit_tests` target with `BUILD_TESTS=ON`, no
  enclave/chain, and gated by conformance against the Python oracle
  (`tools/sd_cwt/tests/test_cpp_conformance.py`): a pinned Redacted-Claim-Hash
  vector, Python `validate`ing C++ tokens for signature + disclosures, a
  byte-identical payload check, cross-validation of array-element (tag 60) and
  deep-nested + ancestor-disclosure redaction, a byte-identical decoy-padding
  check, a `cnf` key-binding check where Python recovers the embedded holder key,
  and a full KBT check where Python `kbt_verify` accepts a C++-signed Key Binding
  Token.
  Supports map, nested-map and array-element (tag 60) redaction
  at arbitrary depth via `redact_paths` under the ancestor-disclosure rule,
  matching the Python reference, so layered disclosures are available. The statement
  schema still redacts `references` whole for strict uniformity, but the core can
  redact individual elements when a policy needs it. Decoy padding
  (`issue(..., pad_to=N)`) is ported too; it pads the top-level Redacted-Claim-Hash
  count to N with indistinguishable salt-only decoys, byte-identical to the
  Python reference under fixed salts and pinned by conformance. Key binding: the
  issuer can bind a token to a holder key by embedding the RFC 8747 confirmation
  claim (`issue(..., holder=pub)` → clear `8: {1: COSE_Key}`), so the enclave
  issues fully standards-compliant, key-binding-capable SD-CWTs; a conformance
  test recovers the `cnf` key in Python and checks its coordinates + fixed-length
  encoding. Presentation + Key Binding Token signing are also ported:
  `present()` attaches selected disclosures to the SD-CWT unprotected header
  (`sd_claims`, 17) without re-signing, and `kbt_sign()` wraps the presented
  SD-CWT in the KBT `kcwt` (13) protected header and signs it with the holder
  key, using typ application/kb+cwt. A conformance test has the Python
  reference `kbt_verify` accept a C++-signed KBT end-to-end: issuer signature,
  `cnf` proof-of-possession, audience/cnonce, selective disclosure. Only
  `kbt_verify` stays Python: it is the *verifier's* check, off-chain by design.
- `make_disclosure` / `verify` off-chain tooling.

**Dependency:** vendor QCBOR via CMake `FetchContent`.

## 14. Off-chain token tooling: `sd_cwt` (Python)
**Decision: service signs.** Every statement is constructed and signed by the
service in C++, not by the submitter; researchers submit raw content. The Python
token tooling, issue/sign/redact/present/verify/validate, is therefore both the
reference oracle mirroring the C++ issuer construction and the researcher-side
offline verifier, through `validate` or the receipt-anchored `validate_trusted`.
Here the service is the sole signer; submitters never sign.

`sd_cwt` is our own minimal, domain-agnostic package in-repo at
`tools/sd_cwt/`, src-layout, with its own `pytest` suite. The core operates on
arbitrary CBOR claims; the unified report/note schema from §1 plus
strict-uniformity / `parent` rules live in the `sd_cwt.statement` layer on top.

**Implemented subset, our custom profile:**
- COSE_Sign1 issuer-signed CWT via pycose.
- Map-entry redaction (`redacted_claim_keys` = `simple(59)`) and
  array-element redaction (tag `60`).
- Disclosures `[salt,value,key]` / `[salt,value]` in the unprotected header
  (`sd_claims`, label 17). The Redacted Claim Hash is taken over the
  `bstr`-encoded disclosure, per the CDDL / Appendix G, matching the
  reference example tokens.
- Nested / recursive redaction at arbitrary depth (`redact_paths`), including
  the ancestor-disclosure rule. A disclosed parent may reveal a still-redacted
  child.
- Hash-alg agility driven by the protected `sd_alg` header (SHA-256/384/512;
  default SHA-256). `validate` reads `sd_alg` from the header.
- **Decoy padding:** `issue(..., pad_to=N)` pads the redacted-slot count to N with
  random decoy digests → supports the uniform-token-shape principle.
- Key Binding Tokens (`kbt_sign`/`kbt_verify`) with RFC 8747 `cnf`
  proof-of-possession. Included for spec compliance only; not used in the
  core flow. The transparency-service receipt, for example a CCF ledger receipt,
  is the app's binding anchor, and the verification path is the receipt-anchored
  `validate_trusted`. That is why the signature-free `match_disclosures` is
  factored out of `verify`.
- **Encoding MUSTs on untrusted input:** definite-length (s5.1), finite date-claim
  encodings (s5.2), map-key type/length (s5.3), duplicate-map-key rejection (s5.4),
  nesting depth ≤16 (s5.5); plus duplicate disclosed-key rejection and both the
  KBT and SD-CWT audience checks (s9).
- CSPRNG for all crypto randomness (salts, decoys) via `secrets`.
- **Deterministic (CDE) emission:** the issuer/holder canonicalises everything it
  emits: the SD-CWT and KBT protected headers and payloads, and every Salted
  Disclosed Claim. It uses RFC 8949 §4.2.1 bytewise map-key order (`_cde` /
  `_cde_header`), so the reference is byte-identical to the C++ token core,
  including headers, and the issuer covert channel from key ordering (§15.2/
  §16.7) is closed. This is a privacy profile choice, not a wire-format MUST.
  Only definite-length is. Note: cbor2's own `canonical=True` uses length-first
  ordering (§4.2.3), which diverges from CDE for maps mixing multi-byte unsigned
  and negative keys, so ordering is done explicitly.

**Deliberately omitted:** temporal *validity* comparison for `exp`/`nbf`/`iat`
against a clock. The ledger receipt/seqno covers ordering; only the s5.2
*encoding* checks are enforced. The claim values are surfaced via
`validate().clear` and `KBTResult.kbt_claims` so the app layer can run its own
temporal checks. Also omitted: AEAD-encrypted disclosures; pre-issuance
To-Be-Redacted / To-Be-Decoy tags.

**API, what tests target:**
```
issue(claims, redact, signer, *, redact_elements=None, redact_paths=None,
      sd_alg=SHA256, pad_to=None, cnf=None)             -> (token, [Disclosure])
present(token, selected: [Disclosure])                  -> token
verify(token, pubkey)                                   -> VerifiedToken
validate(token, pubkey)                                 -> ValidatedClaims{clear, disclosed}
validate_trusted(token)                                 -> ValidatedClaims   # skip sig; trust from receipt
match_disclosures(payload, presented, *, sd_alg=SHA256) -> ValidatedClaims
kbt_sign(token, selected, holder, *, aud, iat=None, cti=None, cnonce=None) -> kbt
kbt_verify(kbt, issuer_pub, *, expected_aud, expected_cnonce=None)         -> KBTResult
```

**Statement layer (`sd_cwt.statement`):** the report/note schema on top:
```
issue_statement(signer, *, iss, iat, parent=None, title=None, body=None,
    component=None, severity=None, fingerprint=None, references=None,
    patch=None, patch_date=None)                        -> (token, [Disclosure])
disclosures_for(discs, *field_names)                    -> [Disclosure]
validate_statement(token, issuer_pub)                   -> ValidatedClaims  # sig + schema
validate_statement_trusted(token)                       -> ValidatedClaims  # receipt-trust + schema
redacted_shape(token)                   -> (clear_keys, n_redacted)  # uniformity invariant
```
