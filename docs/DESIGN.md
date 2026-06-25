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
| Reporter / Issuer (originals) | **Researchers** | sign and submit reports **directly** to the service |
| Issuer (follow-ups) | **the Operator** | submits follow-up notes referencing a report |
| Notary / Transparency service | **CCF service in a TEE** | registers statements, assigns **seqno**, issues **signed receipts**, forwards report to the Operator; trust domain **separate** from the Operator |
| Holder of disclosures | **the Operator (self-custody)**; optional service backup | only the holder of salt/value can disclose |
| Verifier | a **researcher** | verifies **offline** |

**Core flow:** reports go **researcher → service → the Operator**, never the Operator → service.
This blocks the Operator **front-running** (it only sees a report after the service has
already assigned a seqno). The Operator enriches the record afterward via **follow-ups**
to make later duplicate-proofs easier.

## 4. Authentication / registration model (notary)
The service is a **notary**, not an identity authority.
- **No issuer key enrollment.** Researcher/Operator keys are NOT CCF users. The
  receipt proves "this blob existed at seqno T," nothing about who signed.
- **Signature trust is the verifier's job, offline**, against well-known pubkeys
  (the Operator anchor; reporter's claimed key).
- Submission-time check = **sanity check**: parse the COSE_Sign1 and verify
  its signature against the key **carried in the statement** (`kid`/`x5chain`).
  Rejects malformed/garbage; does **not** enforce *who*; needs **no registration**.
- Operator-follow-up authorization (optional, later): a **config-pinned Operator pubkey**
  (governance-set), or leave to the offline verifier.
- Optional anti-spam access control (rate-limit/JWT) is orthogonal.

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
- **Issuer-signature forgery** — verifier checks sigs against well-known pubkeys.
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
COSE_Sign1 (issuer-signed: researcher or the Operator):
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
| `DisclosuresTable` | private (encrypted) | id → `[salt,value,key]` tuples — **OPTIONAL, feature-flagged backup** |

- the Operator **self-custodies** its follow-up disclosures; `DisclosuresTable` is an
  optional service-side backup (durability/availability), default off.
- Follow-ups reference parent **by hash** (the always-full field); ordering /
  precedence **by seqno**.

## 9. Endpoints & off-chain tooling
**Service endpoints:**
- `submit_report` (researchers, direct): L2 sanity check → store redacted token,
  set claims digest → return **seqno + receipt**; make content available to the Operator;
  (optional) back up disclosures.
- `append_follow_up` (the Operator): store redacted follow-up (`parent_report` set),
  set claims digest → return receipt; index under parent.
- read helpers: `get_report` (the Operator pulls content), `get_receipt`, `list_notes`.

**Off-chain (NOT endpoints):**
- `make_disclosure(id, fields)` — **Operator-side, offline.** Only the disclosure
  holder can run it; assembles `{ redacted token, receipt, selected disclosures }`.
- `verify` — **researcher-side, offline.** issuer sig over payload → service sig
  over claims digest → hash-match disclosures.

**Duplicate proof:** The Operator runs `make_disclosure` on the **earlier** matching
follow-up; verifier checks **seqno M < their seqno N** and that the disclosed
field matches their bug.

OPEN: confidential delivery of report content service→Operator (encrypt-to-Operator vs
TEE-mediated forwarding) while the public ledger holds only the redacted form.

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
6. **(optional) hardening** — service→Operator delivery mechanism, optional
   `DisclosuresTable` backup, redact linkage, config-pinned issuer authorization,
   anti-spam controls, KBT for external subjects.

## 11. Caveats / open decisions
- Disclosure artifact: separate-bundle (preferred) vs embedded profile.
- RESOLVED: `parent_report` is redacted by default + always present (no metadata leak).
- Principle: redacted tokens leak no metadata; keep token shape uniform.
- "Operator can't read confidential state" is deployment/attestation-dependent.
- OPEN: confidential report delivery service→Operator.
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
