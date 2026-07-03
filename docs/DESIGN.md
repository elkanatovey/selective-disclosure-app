# Selective Disclosure App — Design & Plan

A confidential, append-only **bug-report ledger** built on CCF (from
source). Reports are registered in a TEE-backed transparency service so that
their existence/ordering is provable, their contents stay hidden by default, and
The Operator can **selectively reveal** specific fields to prove a new submission is a
**duplicate** — without exposing the rest.

Status: design agreed; implementation starts from the in-repo `basic` sample
(currently `app/src/app.cpp`, a plain key/value store).

---

## 1. Goal / use case
- Registration is **provable & tamper-evident** via monotonic **seqno** ordering.
- Report contents are **hidden by default**.
- the Operator can **selectively disclose** chosen fields to a researcher to **prove a
  duplicate**, revealing nothing else.

A report is a multi-field object: `report_text` (+ time), optional
`classification`, optional `patch` (+ date), and a **`parent_report`** reference.
Follow-up notes are optional and added later.

### Terminology: report vs note (same object, different role)
A **report** and a **note/follow-up** are the **same kind of object** — an SD-CWT
statement with fields + the always-full `parent_report`. They differ only by role:
- **report** = a *root* statement (original submission, typically by a
  **researcher**; `parent_report` = none/garbage).
- **note / follow-up** = a *child* statement (later addition by **the Operator**:
  classification, patch, detail; `parent_report` = a real report).

Recommended: **one unified "statement" schema**, with root-vs-child distinguished
purely by `parent_report`. ("Notes" always means the Operator follow-ups, never the
original report.)

### TODO: define the statement schema  (todo: define-report-fields)
Specify the unified schema (report + note): every claim key (private-use int or
string), its meaning, and **clear vs selectively-disclosable** per field;
`parent_report` is **redacted-by-default and always present**; design a **uniform
token shape** so redacted tokens leak no metadata; reserve standard CWT keys and
SD labels. Prerequisite for Phase 2.

## 2. Report structure
- Multi-field object; one field is **`parent_report`**.
- **`parent_report` is mandatory and constant-shape — always present, padded with
  garbage when there is no real parent.**
- `parent_report` is **selectively-disclosable and redacted by
  default** — in a stored/redacted token it appears only as a Redacted Claim
  Hash, leaking nothing (not even *whether* a parent exists). The Operator discloses the
  linkage only when it wants to prove it.
- **Principle: a redacted token must leak no metadata.** The token *shape* (which
  claims appear, the count of redacted entries) should be **uniform** across
  statements regardless of content, so the pattern itself reveals nothing.

## 3. Roles & trust model
| Role | Who | Notes |
|---|---|---|
| Reporter (originals) | **Researchers** | submit **raw report content** directly to the service (authenticated channel) |
| Follow-ups | **the Operator** | submits follow-up note content referencing a report |
| Notary / Transparency service | **CCF service in a TEE** | **constructs + signs** the SD-CWT, registers it, assigns **seqno**, issues **signed receipts**, holds the confidential store; trust domain **separate** from the Operator |
| Holder of disclosures | **the service** (default, `store_unredacted`) or **Operator self-custody** (flag off) | only the holder of salt/value can disclose |
| Verifier | a **researcher** | verifies **offline** via the receipt (`validate_trusted`) |

**Core flow:** reports go **researcher → service → the Operator**, never the Operator → service.
This blocks the Operator **front-running** (it only sees a report after the service has
already assigned a seqno). The Operator enriches the record afterward via **follow-ups**
to make later duplicate-proofs easier.

## 4. Authentication / registration model (notary)
The service is a **notary + signer**, not an identity authority.
- **The service (TEE) is the sole signer.** Researchers/Operator submit **raw
  content** over an authenticated channel; the service constructs and signs the
  SD-CWT. There is no per-submitter statement signature to check.
- **No key enrollment.** Submitter identity is not a CCF user set; the receipt
  proves "this statement existed at seqno T", signed by the service.
- **Verification is receipt-anchored** (`validate_trusted`): a verifier trusts
  the statement because of the service signature + receipt, not by re-checking a
  submitter's key. Submitter authorship "beyond that doesn't matter" for the
  core flow.
- Submitter authentication is a **transport/channel** concern (who may submit),
  orthogonal to the statement signature; optional anti-spam (rate-limit/JWT) sits
  here.
- **Operator authorization is mandatory for confidential-egress endpoints**
  (`get_statements_since`, `get_statement`, `make_disclosure` — §9): these return
  plaintext, so they are gated to a config-pinned / governance-set Operator
  identity. (This is the one place caller authentication is required; submission
  itself needs none.)

## 5. Threat model
**Defended:**
- **Operator front-running researchers** — direct researcher→service submission
  anchors precedence (seqno) before the Operator sees the report.
- **Operator backdating / fabricating precedence** — TEE-signed receipt + monotonic
  seqno; a fabricated "earlier" statement can only get a *current* seqno.
- **Log tampering** — append-only Merkle ledger, service-signed.
- **Over-disclosure** — selective disclosure reveals only matching field(s);
  the rest remain salted hashes.
- **Content exposure to auditors / replicas** — public ledger entry holds only
  the redacted/committed form.
- **Disclosure forgery** — `hash ∈ signed payload` + collision resistance.
- **Statement-signature forgery** — the service (TEE) signs; verifiers check
  against the service cert / attestation-rooted key.
- **Linkage / metadata leakage** — `parent_report` is always-present AND redacted;
  uniform token shape leaks no metadata (not even whether a parent exists).

**Assumptions / trusted:** TEE attestation holds (only attested code wields the
service key / sees confidential state — strength is deployment-dependent); issuer
keys secure; verifiers hold Operator pubkey + service cert/endorsements as
out-of-band trust anchors; salts high-entropy.

## 6. Cryptographic building blocks
- **COSE_Sign1** — researcher/Operator-signed statements; verifying key may ride in
  the statement.
- **SD-CWT** (draft-ietf-spice-sd-cwt-08) — salted-hash redaction: disclosable
  fields → Redacted Claim Hashes in the signed payload (`redacted_claim_keys =
  simple(59)`; array elements via tag `60`); `[salt, value, key]` disclosures in
  the **unprotected header** (`sd_claims`, label 17). Reveal by hash-match;
  redact by dropping disclosures — signature unaffected.
- **CCF receipt** — service-signed inclusion proof binding the **claims digest**;
  offline-verifiable with the service cert.
- **SHA-256** + **CBOR**.
- Present in the built CCF (call directly): COSE sign/verify, `ccf::cose::edit::
  set_unprotected_header`, receipt APIs (`describe_merkle_proof_v1`,
  `describe_cose_signature_v1`, `build_receipt_for_committed_tx`), SHA-256.
- **CBOR encode/decode is NOT exposed by CCF** for general use — we vendor
  **QCBOR** via CMake `FetchContent` (as SCITT does) to build/parse token bytes.
- CCF-source modification is **last resort**.

## 7. The disclosure artifact
Prefer **(b) separate standard bundle**: hand the verifier three standard
objects `{ SD-CWT, receipt, disclosures }`. Nothing non-standard; the verifier
runs three standard checks (COSE sig-check; SD-CWT hash-match; receipt-check).

Alternative **(a) embedded**: receipt + selected disclosures placed in the
SD-CWT's unprotected header → one self-contained COSE_Sign1 (a standard COSE
object carrying a standard *combination* of SD-CWT + transparency receipt; no
single spec names the combo, so no off-the-shelf tool validates it as one unit).

```
COSE_Sign1 (service-signed, TEE):
  protected   : { alg, sd_alg(SHA-256), typ }
  payload     : { clear fields,
                  redacted_claim_keys:[hashes incl. always-present parent_report] }
  unprotected : { receipt: <service-signed>,        # (a) only
                  sd_claims:[selected disclosures] } # (a) only
```

## 8. Data model (KV tables)
| Table | Visibility | Key → Value |
|---|---|---|
| `ReportsTable` | public | id → **redacted SD-CWT** bytes (blob write, à la SCITT `EntryTable`) |
| `NotesIndex` | public | report id → [follow-up seqnos] |
| `ConfidentialTable` | private (encrypted) | id → the report's **full list of per-field/per-element disclosures** (each `[salt,value,key]` or `[salt,value]`, annotated with its **path**) — **feature-flagged, default ON** |

- **Signing:** the **service (TEE)** constructs and signs the SD-CWT (trust roots
  in attestation); researchers submit raw content over an authenticated channel.
  The receipt-anchored `validate_trusted` is the verification path.
- **Confidential store (`store_unredacted`, default ON):** the service holds the
  report's disclosures (= the unredacted values for redacted fields; with the
  public token's clear fields this reconstructs the full report). Chosen for
  implementation ease — it dissolves the separate confidential-delivery channel
  and lets the service produce duplicate-proofs directly.
- **Granular + recursive disclosure:** the store keeps the **individual**
  disclosures (NOT a monolithic plaintext blob) so `make_disclosure` can reveal
  an arbitrary subset at any depth. Because nested disclosure follows the
  ancestor-disclosure rule, each disclosure is annotated with its **full path**,
  and `make_disclosure(target_paths)` selects the targets **plus their ancestor
  disclosures**. (Likely a small `sd_cwt` helper: given all disclosures + target
  paths, return the minimal disclosure set incl. ancestors.)
- **Segregation invariant (for easy migration):** the redacted-token build,
  claims-digest binding, receipt issuance and the public store **never read**
  the confidential store. It is *write-only* from the submit path and *read-only*
  from `make_disclosure`. Turning `store_unredacted` OFF is then a one-site
  change — disclosures move to Operator self-custody (§9); an encrypt-to-Operator
  variant is just a change to this table's value format.
- **Immutability caveat:** the CCF ledger is append-only, so entries written
  while the flag is ON retain their (encrypted) disclosures permanently. The flag
  controls future writes, not past ones — migration affects new entries only.
- **Salts are random (CSPRNG), per field — the production choice.** Each
  disclosure carries an independent 128-bit random salt (what `sd_cwt` already
  does). Rationale: the only benefit of *deterministic* salts
  (`salt = HMAC(K_salt, id‖path)`) is not having to store salts, but since the
  service stores the confidential data anyway that benefit is moot here — while
  deterministic salts cost a sealed single-purpose `K_salt` (never the signing
  key), a strict canonical-encoding requirement, and a real leak surface
  (hash-equality reveals input-equality, so cross-report values must be blinded
  by binding a unique id + full path). Random salts blind every occurrence
  independently, add no key management, and are the least-surprise, spec-aligned
  default. Since a disclosure *is* `(salt,value,key)`, "store the disclosures"
  already stores the salts — no change to `issue()`.
  *(Deferred option: deterministic salts, only if a future model deliberately
  minimises stored confidential state — store just the redacted token + `K_salt`
  and reconstruct — and only with strict id+path binding.)*
- Follow-ups reference parent **by hash** (the always-full field); ordering /
  precedence **by seqno**.

## 9. Endpoints & off-chain tooling
**Service endpoints:**
- `submit_report` (reporter, direct): store redacted token (public) + the report's
  disclosures (confidential), set claims digest → **return seqno + receipt to the
  reporter** (their proof-of-registration and precedence anchor).
- `append_follow_up` (Operator): store redacted follow-up (`parent_report` set),
  set claims digest → return receipt; index under parent.
- `get_statements_since(cursor_seqno, limit)` (**Operator only**): the unredacted
  stream — **all** statements (original reports **and** follow-ups) registered
  after `cursor_seqno`, in seqno order, each with its receipt. The Operator keeps
  its own cursor (high-water seqno) and advances it; service-side stateless,
  idempotent to replay. Reuses CCF seqno-indexed historical queries.
- `get_statement(id)` (**Operator only**): pull a single unredacted statement +
  receipt by id.
- `make_disclosure(id, target_paths)` (**Operator only**): assemble
  `{ redacted token, receipt, disclosures for target_paths + their ancestors }`
  from the confidential store, for the Operator to hand a researcher. *(Reverts to
  offline Operator-side tooling when `store_unredacted` is OFF — self-custody.)*
- read helpers: `get_report` (public **redacted** token), `get_receipt`,
  `list_notes`.

**Confidential-egress authorization:** `get_statements_since`, `get_statement`,
and `make_disclosure` return confidential plaintext and MUST be gated to the
**Operator** (config-pinned / governance-set identity). This is distinct from the
notary/no-enrollment stance for submission (§4).

**Off-chain (NOT a service endpoint):**
- `verify` — **researcher-side.** Checks the service signature + receipt and
  hash-matches disclosures (`validate` / `validate_trusted`).

**Duplicate proof:** The Operator runs `make_disclosure` on the **earlier** matching
statement; verifier checks **seqno M < their seqno N** and that the disclosed
field matches their bug.

## 10. Phased build order (from today's `basic` app)
**Build the off-chain token layer first, then the on-chain service on top.**
Token creation (CBOR/COSE/SD-CWT) is a prerequisite layer; receipts and seqno
are chain logic that *consumes* those tokens.

0. **Define the statement schema** (todo: define-report-fields) — unified
   report/note fields, clear vs SD per field, redacted-always-present
   `parent_report`. Prerequisite for everything.
1. **Off-chain: build + sign a plain CWT** — schema-valid CBOR claims set wrapped
   in COSE_Sign1; verify round-trip. Standalone lib + CLI + unit tests, no chain.
   (Nails the QCBOR + COSE + signing pipeline.)
2. **Off-chain: SD-CWT redaction** — add salts / disclosures / Redacted Claim
   Hashes; round-trip: build → redact → disclose subset → verify. Still no chain.
3. **On-chain: submit + receipt** — `submit_report` consumes a token: sanity
   check, store the blob, bind claims digest, return **seqno + receipt**.
   (Receipt/seqno are chain logic layered on top of steps 1–2.)
4. **Follow-ups & linkage** — `append_follow_up`, redacted `parent_report`,
   `NotesIndex`, seqno ordering.
5. **Disclosure & duplicate proof** — offline `make_disclosure` + `verify`;
   end-to-end demo.
6. **(optional) hardening** — `store_unredacted` OFF (Operator self-custody) or
   encrypt-to-Operator, redact linkage, config-pinned issuer authorization,
   anti-spam controls, KBT for external subjects (**already implemented in the
   `sd_cwt` lib**; wiring into the app is what remains).

## 11. Caveats / open decisions
- Disclosure artifact: separate-bundle (preferred) vs embedded profile.
- RESOLVED: `parent_report` is redacted by default + always present (no metadata leak).
- RESOLVED (for now): the **service (TEE) signs** statements; the **service holds
  the unredacted disclosures** in a private table (`store_unredacted`, default
  ON), segregated for easy migration. This dissolves the confidential
  service→Operator delivery channel for the initial implementation.
- Principle: redacted tokens leak no metadata; keep token shape uniform.
- "Operator can't read confidential state" is deployment/attestation-dependent —
  and now load-bearing for whole reports (not just disclosures), since the
  service holds plaintext in an encrypted private table.
- Each layer is standard; only the embedded *combination* is non-standard.

## 12. Implementation: reuse map & layering
**Two layers, built in order:**
1. **Off-chain token layer (build first):** create + sign + redact + verify the
   COSE_Sign1 / SD-CWT tokens. Pure client-side crypto (CBOR + COSE + SHA-256),
   no chain — fast unit-test iteration.
2. **On-chain service layer (on top):** registration, **seqno**, **receipts**,
   storage — chain logic that *consumes* tokens from layer 1. Token creation is
   therefore a **prerequisite** to receipt generation.

**Reuse from CCF (call directly, already installed):**
- `ccf::cose::edit::set_unprotected_header` (+ `desc::Value/Empty`, `pos::AtKey`)
- receipt APIs: `describe_merkle_proof_v1`, `describe_cose_signature_v1`,
  `build_receipt_for_committed_tx`
- COSE verify, SHA-256, KV (`Map`/`Value`/`RawCopySerialisedValue`), seqno indexing.

**Reuse from SCITT (copy & adapt into `app/`, Apache-2.0):**
- `cbor.h` (QCBOR helpers) — ~as-is
- `cose.h` (COSE_Sign1 decode, header/COSE_Key parse, hash) — strip TSS/DID bits
- `get_cose_receipt()` (CCF receipt → COSE receipt) — directly
- register / local-commit flow → template for `submit_report`
- `historical_queries_adapter.h` + `SeqnosForValue` indexing → seqno lookup
- the QCBOR `FetchContent` block in `app/CMakeLists.txt`
- optional: `configurable_auth.h` (empty/JWT) if we add access control

**Not reused:** `verifier.h` (did:x509 / JWKS) → replaced by a ~50-line
self-contained verifier; `policy_engine.h`; SCITT governance endpoints.

**New code (the novel parts):**
- `sd_cwt` library — redaction core (salts, disclosures, Redacted Claim Hashes,
  `redacted_claim_keys` / tag 60). Built as a **shared library** that compiles
  into both a standalone CLI + unit tests **and** the CCF app.
- statement schema; `make_disclosure` / `verify` off-chain tooling.

**Dependency:** vendor **QCBOR** via CMake `FetchContent`.

## 13. Off-chain token tooling: `sd_cwt` (Python)
**Decision:** the off-chain token tooling (issue/sign/redact/present/verify/validate)
is **Python**, wrapping **pycose** (as SCITT's `pyscitt` does, `pycose==1.1.0`) +
`cbor2` + `hashlib`. The in-TEE C++ app only does **verify + store** (reuse CCF's
`make_cose_verifier_from_key`). Token *creation/redaction* is client-side, matching
SCITT's "sign client-side, verify in C++" split.

**`sd_cwt` is our own minimal, domain-agnostic package** (in-repo at `tools/sd_cwt/`,
src-layout, own `pytest` suite). It operates on arbitrary CBOR claims; the
report/note schema + `parent_report` rules live in the app/issuer layer on top.

**Implemented subset (our custom profile):**
- COSE_Sign1 issuer-signed CWT via pycose.
- **Map-entry** redaction (`redacted_claim_keys` = `simple(59)`) **and**
  **array-element** redaction (tag `60`).
- Disclosures `[salt,value,key]` / `[salt,value]` in the unprotected header
  (`sd_claims`, label 17). The Redacted Claim Hash is taken over the
  **`bstr`-encoded** disclosure (per the CDDL / Appendix G), matching the
  reference example tokens.
- **Nested / recursive redaction** at arbitrary depth (`redact_paths`), including
  the ancestor-disclosure rule (a disclosed parent may reveal a still-redacted
  child).
- **Hash-alg agility** driven by the protected `sd_alg` header (SHA-256/384/512;
  default SHA-256) — `validate` reads `sd_alg` from the header.
- **Decoy padding:** `issue(..., pad_to=N)` pads the redacted-slot count to N with
  random decoy digests → supports the uniform-token-shape principle.
- **Key Binding Tokens** (`kbt_sign`/`kbt_verify`) with RFC 8747 `cnf`
  proof-of-possession — included for **spec compliance only**; not used in the
  core flow. The transparency-service receipt (e.g. a CCF ledger receipt) is the
  app's binding anchor, and the verification path is the receipt-anchored
  `validate_trusted` (which is why the signature-free `match_disclosures` is
  factored out of `verify`).
- **Encoding MUSTs on untrusted input:** definite-length (s5.1), finite date-claim
  encodings (s5.2), map-key type/length (s5.3), duplicate-map-key rejection (s5.4),
  nesting depth ≤16 (s5.5); plus duplicate disclosed-key rejection and both the
  KBT and SD-CWT audience checks (s9).
- **CSPRNG for all crypto randomness** (salts, decoys) via `secrets`.

**Deliberately omitted:** temporal *validity* comparison (`exp`/`nbf`/`iat`
against a clock — the ledger receipt/seqno covers ordering; only the s5.2
*encoding* checks are enforced; the claim **values are surfaced** via
`validate().clear` and `KBTResult.kbt_claims` so the app layer can run its own
temporal checks); AEAD-encrypted disclosures; pre-issuance To-Be-Redacted /
To-Be-Decoy tags.

**API (what tests target):**
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
