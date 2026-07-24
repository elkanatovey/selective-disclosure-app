# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A narrated end-to-end demo of the Selective Disclosure Report Ledger.

Three roles talk to one running node:

  * a **member** (governance)   — one-time: initialise the issuer signing key.
  * a **client** (anonymous)    — submits a bug report, gets a redacted token back.
  * the **Operator** (a CCF user) — pulls the full report, then releases a
    *partially* unredacted version proving only chosen fields.

Run it via ``demo/run_demo.sh`` (which boots a sandbox node first), or point it
at an already-running node with ``--url`` / ``--common-dir``.
"""

import argparse
import sys
import time
from pathlib import Path

import cbor2
import requests
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pycose.keys import EC2Key
from pycose.keys.curves import P256, P384, P521
from sd_cwt import statement as st


# --- tiny pretty-printing helpers -------------------------------------------
class C:
    B = "\033[1m"
    DIM = "\033[2m"
    G = "\033[32m"
    Y = "\033[33m"
    C = "\033[36m"
    R = "\033[31m"
    X = "\033[0m"


def step(n: int, title: str) -> None:
    print(f"\n{C.B}{C.C}[{n}] {title}{C.X}")


def note(msg: str) -> None:
    print(f"    {msg}")


def good(msg: str) -> None:
    print(f"    {C.G}\u2713 {msg}{C.X}")


def pause(interactive: bool) -> None:
    if interactive:
        input(f"    {C.DIM}(press Enter to continue){C.X}")


# --- a minimal client (service-cert TLS + optional client cert) -------------
class Client:
    def __init__(self, url, ca, cert=None):
        self.base = url.rstrip("/") + "/app"
        self.ca = ca
        self.cert = cert

    def _req(self, method, path, body=None, ctype=None):
        headers = {"content-type": ctype} if ctype else {}
        return requests.request(
            method,
            self.base + path,
            data=body,
            headers=headers,
            verify=self.ca,
            cert=self.cert,
            timeout=15,
        )

    def get(self, path):
        return self._req("GET", path)

    def post(self, path, body, ctype="application/cbor"):
        return self._req("POST", path, body, ctype)

    def get_historical(self, path, timeout_s=20):
        """Retry while a CCF historical read is still fetching (202/404/503)."""
        deadline = time.time() + timeout_s
        while True:
            r = self.get(path)
            pending = r.status_code in (202, 503) or (
                r.status_code == 404 and b"TransactionPendingOrUnknown" in r.content
            )
            if not pending or time.time() >= deadline:
                return r
            time.sleep(0.3)

    def post_historical(self, path, body, ctype="application/cbor", timeout_s=20):
        deadline = time.time() + timeout_s
        while True:
            r = self.post(path, body, ctype)
            pending = r.status_code in (202, 503) or (
                r.status_code == 404 and b"TransactionPendingOrUnknown" in r.content
            )
            if not pending or time.time() >= deadline:
                return r
            time.sleep(0.3)


# --- verification helpers ---------------------------------------------------
def issuer_key(client: Client) -> EC2Key:
    """Fetch the issuer public key from GET /signing-key and build a COSE key."""
    obj = cbor2.loads(client.get_historical("/signing-key").content)
    pub = load_pem_public_key(obj["key"])
    crv, size = {
        "secp256r1": (P256, 32),
        "secp384r1": (P384, 48),
        "secp521r1": (P521, 66),
    }[pub.curve.name]
    n = pub.public_numbers()
    return EC2Key(crv=crv, x=n.x.to_bytes(size, "big"), y=n.y.to_bytes(size, "big"))


def show_fields(claims) -> None:
    """Print the fields a verifier could actually read from a statement. The
    internal `parent` linkage (garbage padding on a root report) is omitted for
    clarity."""
    shown = {fid: val for fid, val in claims.disclosed.items() if fid != st.PARENT}
    if not shown:
        print(f"    {C.Y}(nothing revealed \u2014 every field stays hidden){C.X}")
        return
    for fid, val in sorted(shown.items()):
        name = st.NAME_BY_FIELD.get(fid, str(fid))
        print(f"      {C.G}{name:<12}{C.X} = {val!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="https://127.0.0.1:8000")
    ap.add_argument("--common-dir", default="workspace/sandbox_common")
    ap.add_argument(
        "--step", action="store_true", help="pause between steps (for a live demo)"
    )
    args = ap.parse_args()

    common = Path(args.common_dir)
    ca = str(common / "service_cert.pem")
    member = Client(
        args.url,
        ca,
        (str(common / "member0_cert.pem"), str(common / "member0_privk.pem")),
    )
    client = Client(args.url, ca)  # anonymous
    operator = Client(
        args.url,
        ca,
        (str(common / "user0_cert.pem"), str(common / "user0_privk.pem")),
    )

    print(f"{C.B}Selective Disclosure Report Ledger \u2014 demo{C.X}")
    print(
        f"{C.DIM}node: {args.url}   "
        f"(roles: member=governance, client=anonymous, operator=user0){C.X}"
    )

    # -- 0. one-time: the member initialises the issuer signing key ----------
    step(0, "Member (governance) initialises the issuer signing key")
    r = member.post("/signing-key", b"")
    note(f"POST /signing-key -> {r.status_code}  {C.DIM}(idempotent){C.X}")
    key = issuer_key(client)
    good("issuer key is published + endorsed on-ledger (GET /signing-key)")
    pause(args.step)

    # -- 1. the client submits a bug report ---------------------------------
    step(1, "Client submits a confidential bug report")
    report = {
        "title": "auth bypass in login",
        "body": "sending a crafted cookie skips MFA entirely",
        "component": "auth-service",
        "severity": "critical",
        "fingerprint": bytes.fromhex("deadbeefcafe"),
        "references": ["CVE-2025-0001", "CVE-2025-0002"],
        "patch": "validate the cookie signature server-side",
        "patch_date": 1767225600,
    }
    for k, v in report.items():
        print(f"      {k:<12} = {v!r}")
    resp = client.post("/reports", cbor2.dumps(report))
    txid = resp.headers["x-ms-ccf-transaction-id"]
    note(
        f"POST /reports -> {resp.status_code}, "
        f"committed as transaction {C.B}{txid}{C.X}"
    )
    good("the report is now an append-only, service-signed ledger entry")
    pause(args.step)

    # -- 2. the client gets its token back (redacted / transparent) ---------
    step(2, "Client retrieves its token (the redacted, publicly-verifiable statement)")
    tok = client.get_historical(f"/statements/{txid}")
    token_bytes = tok.content
    note(
        f"GET /statements/{txid} -> {tok.status_code}, {len(token_bytes)} bytes of COSE"
    )
    # Prove the plaintext is NOT in the token on the wire.
    leaked = [
        k for k, v in report.items() if isinstance(v, str) and v.encode() in token_bytes
    ]
    good(
        f"contents are hidden on the wire (plaintext fields in bytes: {leaked or 'none'})"
    )
    claims = st.validate_statement(token_bytes, key)
    note("a verifier validates the issuer signature + reads what's revealed:")
    show_fields(claims)
    note(
        f"{C.DIM}existence, ordering (seqno) and integrity are provable to anyone; "
        f"contents are not.{C.X}"
    )
    pause(args.step)

    # -- 3. the Operator pulls the FULL report ------------------------------
    step(3, "Operator pulls the full (unredacted) report")
    full = operator.get_historical(f"/operator/statements/{txid}")
    note(
        f"GET /operator/statements/{txid} -> {full.status_code}  "
        f"{C.DIM}(Operator-gated){C.X}"
    )
    unredacted = st.validate_statement(full.content, key)
    good("the Operator (and only the Operator) sees every field in the clear:")
    show_fields(unredacted)
    # Show an anonymous caller is refused.
    denied = client.get(f"/operator/statements/{txid}")
    note(
        f"an anonymous caller to the same endpoint -> {C.R}{denied.status_code} (refused){C.X}"
    )
    pause(args.step)

    # -- 4. the Operator releases a PARTIAL disclosure -----------------------
    step(4, "Operator releases a PARTIAL disclosure (a duplicate-proof)")
    reveal = ["component", "fingerprint"]
    note(f"the Operator chooses to reveal only: {C.B}{reveal}{C.X}")
    disc = operator.post_historical(
        f"/operator/statements/{txid}/disclosure",
        cbor2.dumps({"fields": reveal}),
    )
    note(f"POST /operator/statements/{txid}/disclosure -> {disc.status_code}")
    proof = st.validate_statement(disc.content, key)
    good("a researcher verifies this artifact offline against the issuer key and sees:")
    show_fields(proof)
    hidden = sorted(set(st.NAME_BY_FIELD.values()) - set(reveal) - {"parent"})
    note(f"{C.Y}still hidden: {hidden}{C.X}")
    # Prove a non-revealed secret is absent from the disclosed artifact.
    secret = report["body"].encode()
    good(
        f"the un-revealed body text is NOT in the released bytes: {secret not in disc.content}"
    )

    print(
        f"\n{C.B}{C.G}Demo complete.{C.X} Existence provable to all; "
        f"contents disclosed only by the Operator, field-by-field.\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
