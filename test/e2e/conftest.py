# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Pytest fixtures for the report-ledger e2e tests.

The ``network`` fixture boots the app as a real CCF node via the installed
``sandbox.sh`` (``--package app/build/selective_disclosure``), waits until it is
open, and yields connection details. It mirrors SCITT's managed-node approach but
reuses CCF's own sandbox rather than a hand-rolled launcher.

Requires the app to be built (``app/build/selective_disclosure``) and the CCF
install tree + ``.venv_ccf_sandbox`` present. Skips cleanly if the app is missing.
"""

import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from client import LedgerClient  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_BINARY = REPO_ROOT / "app" / "build" / "selective_disclosure"
SANDBOX = REPO_ROOT / ".ccf-install" / "bin" / "sandbox.sh"
COMMON_DIR = REPO_ROOT / "workspace" / "sandbox_common"

STARTUP_TIMEOUT_S = 120


@dataclass
class Network:
    base_url: str
    service_cert: str
    common_dir: str

    def client(self, user: str | None = None) -> LedgerClient:
        """A client for the network. With ``user`` (e.g. "user0"), presents that
        member/user cert for ``user_cert_auth`` endpoints."""
        client_cert = None
        if user is not None:
            client_cert = (
                f"{self.common_dir}/{user}_cert.pem",
                f"{self.common_dir}/{user}_privk.pem",
            )
        return LedgerClient(self.base_url, self.service_cert, client_cert)


def _wait_for_node_url(log_path: Path) -> str:
    """Poll the sandbox log until the node advertises its URL; return it. The
    authoritative readiness gate is an endpoint poll (see the fixture); this only
    discovers the address the sandbox chose."""
    deadline = time.time() + STARTUP_TIMEOUT_S
    node_re = re.compile(r"Node \[0\] = (https://\S+)")
    while time.time() < deadline:
        if log_path.exists():
            m = node_re.search(log_path.read_text(errors="replace"))
            if m:
                return m.group(1)
        time.sleep(0.5)
    raise TimeoutError(
        f"sandbox did not report a node URL within {STARTUP_TIMEOUT_S}s; "
        f"see {log_path}"
    )


@pytest.fixture(scope="session")
def network(tmp_path_factory):
    if not APP_BINARY.exists():
        pytest.skip(f"app not built: {APP_BINARY} (run docker/build-app.sh)")
    if not SANDBOX.exists():
        pytest.skip(f"CCF sandbox not found: {SANDBOX}")

    log_path = tmp_path_factory.mktemp("sandbox") / "sandbox.log"
    env = {**os.environ, "VENV_DIR": ".venv_ccf_sandbox"}
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(
            [str(SANDBOX), "--package", "app/build/selective_disclosure"],
            cwd=str(REPO_ROOT),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,  # own process group, for clean teardown
        )
        try:
            base_url = _wait_for_node_url(log_path)
            net = Network(
                base_url=base_url,
                service_cert=str(COMMON_DIR / "service_cert.pem"),
                common_dir=str(COMMON_DIR),
            )
            # Authoritative readiness: the app frontend answers /app/commit.
            client = net.client()
            deadline = time.time() + 30
            ready = False
            while time.time() < deadline:
                try:
                    if client.get("/commit").status == 200:
                        ready = True
                        break
                except Exception:
                    pass
                time.sleep(0.3)
            if not ready:
                raise TimeoutError(
                    f"app frontend not ready at {base_url}; see {log_path}"
                )
            # Initialise + endorse the issuer key on-ledger (submit requires it).
            # Key lifecycle is control-plane governance, so this is member-gated.
            client_member = net.client(user="member0")
            init = client_member.post("/signing-key", b"", "application/cbor")
            if init.status not in (200, 204):
                raise RuntimeError(
                    f"signing-key init failed: {init.status} {init.body!r}"
                )
            yield net
        finally:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=15)
            except Exception:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:
                    pass
