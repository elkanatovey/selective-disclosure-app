# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end disaster-recovery test, mirroring SCITT's ``test_ccf.py::test_recovery``
methodology: submit a report, tear the service down, recover it from the persisted
ledger onto a *new* service identity, and prove that

  * the recovery mechanism is entirely CCF's (``--recover`` drives
    ``governance.recover_service`` via the members' recovery shares — no app code),
  * a receipt issued **before** recovery still verifies afterwards (against the
    predecessor service identity, which recovery preserves), and
  * the recovered service keeps operating: a **new** submission commits and its
    receipt verifies against the **new** service identity.

This is the "does SCITT add functionality here?" question answered as a test: the
continuity is a property of CCF (persisted ledger + preserved previous service
identity), so recovery works with no ledger-app changes. The only recovery-specific
thing SCITT adds is re-exposing CCF's key history via ``/jwks``; here the verifier
instead uses the predecessor cert that CCF's recovery writes to disk
(``predecessor_service_cert.pem``) — the same old key, obtained without a bespoke
endpoint.

Runs its own sandbox on a dedicated port (8001) so it is independent of the
session ``network`` fixture (which owns 8000).
"""

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import cbor2
import requests

sys.path.insert(0, str(Path(__file__).parent))
from client import LedgerClient  # noqa: E402
from conftest import APP_BINARY, REPO_ROOT, SANDBOX, _require  # noqa: E402
from test_reports import _verify_receipt  # noqa: E402

# Recovery replays the whole ledger before the service re-opens, so allow more
# time than a cold start.
READY_TIMEOUT_S = 180
NODE_ADDRESS = "local://127.0.0.1:8001"


def _wait_node_url(log_path: Path, timeout_s: float) -> str:
    node_re = re.compile(r"Node \[0\] = (https://\S+)")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if log_path.exists():
            m = node_re.search(log_path.read_text(errors="replace"))
            if m:
                return m.group(1)
        time.sleep(0.5)
    raise TimeoutError(
        f"sandbox did not report a node URL in {timeout_s}s; see {log_path}"
    )


class _Sandbox:
    """Launch the app under sandbox.sh (optionally in --recover mode) and tear it
    down gracefully so the ledger is flushed for a subsequent recovery."""

    def __init__(
        self, workspace: Path, log_path: Path, recover_from: dict | None = None
    ):
        self.workspace = workspace
        self.log_path = log_path
        self.recover_from = recover_from
        self.proc: subprocess.Popen | None = None
        self.base_url: str | None = None
        self._log = None

    def __enter__(self) -> "_Sandbox":
        args = [
            str(SANDBOX),
            "--package",
            "app/build/selective_disclosure",
            "--workspace",
            str(self.workspace),
            "--node",
            NODE_ADDRESS,
        ]
        if self.recover_from:
            args += [
                "--recover",
                "--ledger-dir",
                self.recover_from["ledger_dir"],
                "--common-dir",
                self.recover_from["common_dir"],
            ]
            snaps = self.recover_from.get("snapshots_dir")
            if snaps and os.path.isdir(snaps) and os.listdir(snaps):
                args += ["--snapshots-dir", snaps]
        env = {**os.environ, "VENV_DIR": ".venv_ccf_sandbox"}
        self._log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            args,
            cwd=str(REPO_ROOT),
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        self.base_url = _wait_node_url(self.log_path, READY_TIMEOUT_S)
        return self

    def wait_open(self, service_cert: str) -> None:
        """Block until the app frontend answers (recovery complete + service open)."""
        client = self.client(service_cert)
        deadline = time.time() + READY_TIMEOUT_S
        while time.time() < deadline:
            try:
                if client.get("/commit").status == 200:
                    return
            except Exception:
                pass
            time.sleep(0.3)
        raise TimeoutError(
            f"app frontend not open at {self.base_url}; see {self.log_path}"
        )

    def client(self, service_cert: str, user: str | None = None) -> LedgerClient:
        cert = None
        if user is not None:
            common = self.workspace / "sandbox_common"
            cert = (str(common / f"{user}_cert.pem"), str(common / f"{user}_privk.pem"))
        return LedgerClient(self.base_url, service_cert, cert)

    def node_network(self, service_cert: str) -> dict:
        """GET the CCF node's /node/network (recovery_count, service_certificate)."""
        r = requests.get(
            f"{self.base_url}/node/network", verify=service_cert, timeout=10
        )
        r.raise_for_status()
        return r.json()

    def __exit__(self, *exc) -> None:
        if self.proc is not None:
            # SIGINT (Ctrl-C) so start_network.py runs its cleanup and the nodes
            # flush the ledger gracefully — required for a clean recovery.
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(os.getpgid(self.proc.pid), sig)
                    self.proc.wait(timeout=30)
                    break
                except Exception:
                    continue
        if self._log is not None:
            self._log.close()


def test_recovery_preserves_ledger_and_receipts(tmp_path_factory):
    _require(
        APP_BINARY.exists(), f"app not built: {APP_BINARY} (run docker/build-app.sh)"
    )
    _require(SANDBOX.exists(), f"CCF sandbox not found: {SANDBOX}")

    workspace = tmp_path_factory.mktemp("recovery_ws")
    common_dir = workspace / "sandbox_common"
    service_cert = str(common_dir / "service_cert.pem")

    # --- Phase 1: original service. Submit a report and capture its transparent
    # statement (receipt embedded), then shut down gracefully. ---
    logs = tmp_path_factory.mktemp("recovery_logs")
    with _Sandbox(workspace, logs / "original.log") as sb:
        sb.wait_open(service_cert)
        member = sb.client(service_cert, user="member0")
        init = member.post("/signing-key", b"", "application/cbor")
        assert init.status in (200, 204), (init.status, init.body)

        user = sb.client(service_cert)
        txid = user.post(
            "/reports", cbor2.dumps({"title": "pre-recovery"}), "application/cbor"
        ).tx_id
        assert txid
        pre = user.get_historical(f"/statements/{txid}")
        assert pre.status == 200, pre.body
        pre_statement = pre.body

        old_cert = Path(service_cert).read_bytes()
        old_net = sb.node_network(service_cert)
        assert old_net["recovery_count"] == 0

    # The pre-recovery receipt verifies against the identity that signed it.
    _verify_receipt(pre_statement, old_cert)

    # --- Phase 2: recover from the persisted ledger onto a NEW service identity. ---
    with _Sandbox(
        workspace,
        logs / "recovered.log",
        recover_from={
            "ledger_dir": str(workspace / "sandbox_0" / "0.ledger"),
            "common_dir": str(common_dir),
            "snapshots_dir": str(workspace / "sandbox_0" / "0.snapshots"),
        },
    ) as sb:
        sb.wait_open(service_cert)

        # CCF minted a fresh service identity; the old one is preserved on disk.
        new_cert = Path(service_cert).read_bytes()
        predecessor_cert = (common_dir / "predecessor_service_cert.pem").read_bytes()
        assert new_cert != old_cert
        assert predecessor_cert == old_cert
        new_net = sb.node_network(service_cert)
        assert new_net["recovery_count"] == 1

        user = sb.client(service_cert)

        # (a) The pre-recovery statement is still retrievable across recovery, and
        #     its (original) receipt still verifies against the predecessor identity.
        recovered = user.get_historical(f"/statements/{txid}")
        assert recovered.status == 200, recovered.body
        _verify_receipt(recovered.body, predecessor_cert)
        _verify_receipt(pre_statement, predecessor_cert)

        # (b) The recovered service keeps working: a new report commits and its
        #     receipt verifies against the NEW service identity. (The issuer signing
        #     key survived recovery on the replayed ledger — no re-init needed.)
        new_txid = user.post(
            "/reports", cbor2.dumps({"title": "post-recovery"}), "application/cbor"
        ).tx_id
        assert new_txid and new_txid != txid
        post = user.get_historical(f"/statements/{new_txid}")
        assert post.status == 200, post.body
        _verify_receipt(post.body, new_cert)
