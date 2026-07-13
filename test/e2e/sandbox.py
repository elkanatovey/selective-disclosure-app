# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""A reusable harness that boots the app as a real CCF sandbox node.

``Sandbox`` launches the installed ``sandbox.sh`` (``--package
app/build/selective_disclosure``), discovers the node URL from its log, waits
until the app frontend is open, builds clients, and shuts the node down
gracefully (SIGINT first, so the ledger is flushed for a later recovery). Both
the session ``network`` fixture (conftest.py) and the disaster-recovery test
(test_recovery.py) use it, so the launch/teardown logic lives in one place.
"""

import os
import re
import signal
import subprocess
import time
from pathlib import Path

from client import LedgerClient

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_BINARY = REPO_ROOT / "app" / "build" / "selective_disclosure"
SANDBOX_SH = REPO_ROOT / ".ccf-install" / "bin" / "sandbox.sh"
PACKAGE = "app/build/selective_disclosure"
VENV_DIR = ".venv_ccf_sandbox"


def _wait_for_node_url(log_path: Path, timeout_s: float, proc) -> str:
    """Poll the sandbox log until the node advertises its URL; return it. Fails
    fast if the node process exits during startup. (Readiness is separately
    gated by an endpoint poll -- see Sandbox.wait_open.)"""
    node_re = re.compile(r"Node \[0\] = (https://\S+)")
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            tail = ""
            if log_path.exists():
                tail = "\n".join(
                    log_path.read_text(errors="replace").splitlines()[-30:]
                )
            raise RuntimeError(f"sandbox node exited during startup:\n{tail}")
        if log_path.exists():
            m = node_re.search(log_path.read_text(errors="replace"))
            if m:
                return m.group(1)
        time.sleep(0.5)
    raise TimeoutError(
        f"sandbox did not report a node URL within {timeout_s}s; see {log_path}"
    )


class Sandbox:
    """Launch + manage a single-node CCF sandbox running the app.

    Usage as a context manager:
        with Sandbox(log_path) as sb:
            sb.wait_open()
            sb.client(user="user0").get(...)

    Options:
      workspace     -- a dedicated workspace dir (adds --workspace); defaults to
                       the sandbox's own ./workspace at the repo root.
      node          -- the node address (adds --node, e.g. local://127.0.0.1:8001);
                       defaults to sandbox.sh's default (127.0.0.1:8000).
      recover_from  -- {ledger_dir, common_dir, snapshots_dir?} to boot in
                       --recover mode from a persisted ledger.
    """

    def __init__(
        self,
        log_path,
        *,
        workspace=None,
        node: str | None = None,
        recover_from: dict | None = None,
        ready_timeout_s: float = 120,
    ):
        self.log_path = Path(log_path)
        self.workspace = Path(workspace) if workspace else None
        self.node = node
        self.recover_from = recover_from
        self.ready_timeout_s = ready_timeout_s
        self.base_url: str | None = None
        self._proc: subprocess.Popen | None = None
        self._log = None
        common_root = self.workspace if self.workspace else (REPO_ROOT / "workspace")
        self.common_dir = common_root / "sandbox_common"
        self.service_cert = str(self.common_dir / "service_cert.pem")

    def __enter__(self) -> "Sandbox":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> "Sandbox":
        args = [str(SANDBOX_SH), "--package", PACKAGE]
        if self.workspace:
            args += ["--workspace", str(self.workspace)]
        if self.node:
            args += ["--node", self.node]
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
        env = {**os.environ, "VENV_DIR": VENV_DIR}
        self._log = open(self.log_path, "wb")
        self._proc = subprocess.Popen(
            args,
            cwd=str(REPO_ROOT),
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,  # own process group, for clean teardown
        )
        self.base_url = _wait_for_node_url(
            self.log_path, self.ready_timeout_s, self._proc
        )
        return self

    def wait_open(self) -> None:
        """Block until the app frontend answers /commit (node open + recovered)."""
        client = self.client()
        deadline = time.time() + self.ready_timeout_s
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

    def client(self, user: str | None = None) -> LedgerClient:
        """A client for the node. With ``user`` (e.g. "user0"/"member0"), presents
        that cert for the mutual-TLS (member/user) endpoints."""
        cert = None
        if user is not None:
            cert = (
                str(self.common_dir / f"{user}_cert.pem"),
                str(self.common_dir / f"{user}_privk.pem"),
            )
        return LedgerClient(self.base_url, self.service_cert, cert)

    def node_network(self) -> dict:
        """GET the CCF node's /node/network (recovery_count, service_certificate)."""
        import requests

        r = requests.get(
            f"{self.base_url}/node/network", verify=self.service_cert, timeout=10
        )
        r.raise_for_status()
        return r.json()

    def stop(self) -> None:
        if self._proc is not None:
            # SIGINT (Ctrl-C) first so start_network.py runs its cleanup and the
            # nodes flush the ledger gracefully -- required for a clean recovery.
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(os.getpgid(self._proc.pid), sig)
                    self._proc.wait(timeout=30)
                    break
                except Exception:
                    continue
            self._proc = None
        if self._log is not None:
            self._log.close()
            self._log = None
