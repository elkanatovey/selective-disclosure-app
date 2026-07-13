# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""End-to-end disaster-recovery test: submit a report, tear the service down,
recover it from the persisted ledger onto a *new* service identity, and prove that

  * the recovery mechanism is entirely CCF's (``--recover`` drives
    ``governance.recover_service`` via the members' recovery shares — no app code),
  * a receipt issued **before** recovery still verifies afterwards (against the
    predecessor service identity, which recovery preserves), and
  * the recovered service keeps operating: a **new** submission commits and its
    receipt verifies against the **new** service identity.

Recovery needs no ledger-app changes: the continuity is a property of CCF
(persisted ledger + preserved previous service identity). A verifier holding a
pre-recovery receipt validates it against the predecessor cert that CCF's recovery
writes to disk (``predecessor_service_cert.pem``) — the same old key, obtained
without any bespoke historical-key endpoint.

Runs its own sandbox on a dedicated port (8001) so it is independent of the
session ``network`` fixture (which owns 8000).
"""

import sys
from pathlib import Path

import cbor2

sys.path.insert(0, str(Path(__file__).parent))
from conftest import _require  # noqa: E402
from helpers import verify_receipt  # noqa: E402
from sandbox import APP_BINARY, SANDBOX_SH, Sandbox  # noqa: E402

# A dedicated port, independent of the session fixture (8000); and a generous
# timeout since recovery replays the whole ledger before the service re-opens.
NODE = "local://127.0.0.1:8001"
READY_TIMEOUT_S = 180


def test_recovery_preserves_ledger_and_receipts(tmp_path_factory):
    _require(
        APP_BINARY.exists(), f"app not built: {APP_BINARY} (run docker/build-app.sh)"
    )
    _require(SANDBOX_SH.exists(), f"CCF sandbox not found: {SANDBOX_SH}")

    workspace = tmp_path_factory.mktemp("recovery_ws")
    common_dir = workspace / "sandbox_common"
    logs = tmp_path_factory.mktemp("recovery_logs")

    # --- Phase 1: original service. Submit a report and capture its transparent
    # statement (receipt embedded), then shut down gracefully. ---
    with Sandbox(
        logs / "original.log",
        workspace=workspace,
        node=NODE,
        ready_timeout_s=READY_TIMEOUT_S,
    ) as sb:
        sb.wait_open()
        init = sb.client(user="member0").post("/signing-key", b"", "application/cbor")
        assert init.status in (200, 204), (init.status, init.body)

        user = sb.client()
        txid = user.post(
            "/reports", cbor2.dumps({"title": "pre-recovery"}), "application/cbor"
        ).tx_id
        assert txid
        pre = user.get_historical(f"/statements/{txid}")
        assert pre.status == 200, pre.body
        pre_statement = pre.body

        old_cert = Path(sb.service_cert).read_bytes()
        old_net = sb.node_network()
        assert old_net["recovery_count"] == 0

    # The pre-recovery receipt verifies against the identity that signed it.
    verify_receipt(pre_statement, old_cert)

    # --- Phase 2: recover from the persisted ledger onto a NEW service identity. ---
    with Sandbox(
        logs / "recovered.log",
        workspace=workspace,
        node=NODE,
        ready_timeout_s=READY_TIMEOUT_S,
        recover_from={
            "ledger_dir": str(workspace / "sandbox_0" / "0.ledger"),
            "common_dir": str(common_dir),
            "snapshots_dir": str(workspace / "sandbox_0" / "0.snapshots"),
        },
    ) as sb:
        sb.wait_open()

        # CCF minted a fresh service identity; the old one is preserved on disk.
        new_cert = Path(sb.service_cert).read_bytes()
        predecessor_cert = (common_dir / "predecessor_service_cert.pem").read_bytes()
        assert new_cert != old_cert
        assert predecessor_cert == old_cert
        new_net = sb.node_network()
        assert new_net["recovery_count"] == 1

        user = sb.client()

        # (a) The pre-recovery statement is still retrievable across recovery, and
        #     its (original) receipt still verifies against the predecessor identity.
        recovered = user.get_historical(f"/statements/{txid}")
        assert recovered.status == 200, recovered.body
        verify_receipt(recovered.body, predecessor_cert)
        verify_receipt(pre_statement, predecessor_cert)

        # (b) The recovered service keeps working: a new report commits and its
        #     receipt verifies against the NEW service identity. (The issuer signing
        #     key survived recovery on the replayed ledger — no re-init needed.)
        new_txid = user.post(
            "/reports", cbor2.dumps({"title": "post-recovery"}), "application/cbor"
        ).tx_id
        assert new_txid and new_txid != txid
        post = user.get_historical(f"/statements/{new_txid}")
        assert post.status == 200, post.body
        verify_receipt(post.body, new_cert)
