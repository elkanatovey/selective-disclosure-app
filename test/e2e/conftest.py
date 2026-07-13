# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Pytest fixtures for the report-ledger e2e tests.

The ``network`` fixture boots the app as a real CCF node via the reusable
``Sandbox`` harness (sandbox.py), waits until it is open, initialises the issuer
signing key, and yields the running sandbox. Convenience fixtures (``anon``,
``operator``, ``service_cert_pem``, ``issuer_key``) build on it.

Requires the app to be built (``app/build/selective_disclosure``) and the CCF
install tree + ``.venv_ccf_sandbox`` present. Skips cleanly if the app is missing.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import helpers  # noqa: E402
from sandbox import APP_BINARY, SANDBOX_SH, Sandbox  # noqa: E402


def _require(present: bool, msg: str) -> None:
    """Skip the e2e suite when a prerequisite is missing locally, but FAIL in CI:
    a green CI run must mean the tests actually ran, never that they were
    silently skipped because the app/sandbox wasn't found."""
    if present:
        return
    if os.environ.get("CI"):
        raise RuntimeError(f"{msg} — refusing to skip the e2e suite in CI")
    pytest.skip(msg)


@pytest.fixture(scope="session")
def network(tmp_path_factory):
    _require(
        APP_BINARY.exists(), f"app not built: {APP_BINARY} (run docker/build-app.sh)"
    )
    _require(SANDBOX_SH.exists(), f"CCF sandbox not found: {SANDBOX_SH}")

    log_path = tmp_path_factory.mktemp("sandbox") / "sandbox.log"
    with Sandbox(log_path) as sb:
        sb.wait_open()  # authoritative readiness: the app frontend answers /commit
        # Initialise + endorse the issuer key on-ledger (submit requires it).
        # Key lifecycle is control-plane governance, so this is member-gated.
        init = sb.client(user="member0").post("/signing-key", b"", "application/cbor")
        if init.status not in (200, 204):
            raise RuntimeError(f"signing-key init failed: {init.status} {init.body!r}")
        yield sb


# --- Convenience fixtures (shared trust-bootstrap + role clients) -----------
@pytest.fixture
def anon(network):
    """An anonymous client (no client cert) — the researcher/public role."""
    return network.client()


@pytest.fixture
def operator(network):
    """The Operator client (user0) for the confidential-egress endpoints."""
    return network.client(user="user0")


@pytest.fixture(scope="session")
def service_cert_pem(network) -> bytes:
    """The service (network) identity certificate bytes — the receipt trust root.
    Session-scoped: the identity is stable for the life of the node."""
    return Path(network.service_cert).read_bytes()


@pytest.fixture
def issuer_key(network, service_cert_pem):
    """The issuer signing key as a verified pycose key: fetched from
    GET /signing-key and checked against the on-ledger endorsement.

    Function-scoped ON PURPOSE — test_signing_key_rotation rotates the key
    mid-session, so a cached key would be stale for later tests."""
    body = network.client().get_historical("/signing-key").body
    return helpers.ec2_key_from_pem(helpers.verify_endorsed_key(body, service_cert_pem))
