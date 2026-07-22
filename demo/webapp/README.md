# Interactive Web Demo

A browser-based, multi-role walkthrough of the Selective Disclosure Report
Ledger. Everything runs inside your dev container; your laptop browser just
connects to it. Open each role in its own window and play them side by side.

```bash
./demo/run_web_demo.sh          # serves http://127.0.0.1:8080
PORT=9000 ./demo/run_web_demo.sh
```

The launcher boots a CCF sandbox node, serves the web UI against it, and tears
the node down on exit. It needs the app built (`./docker/build-app.sh`) and a
CCF install at `./.ccf-install`, exactly like [`run_demo.sh`](../run_demo.sh).

### In a Codespace / dev container

Opening this repo in a Codespace (or "Reopen in Container" in VS Code) runs
[`.devcontainer/post-create.sh`](../../.devcontainer/post-create.sh), which
installs a matching CCF release, points `./.ccf-install` at it, and builds the
app. Once it finishes, just run the launcher — port 8080 is forwarded and opens
in your browser:

```bash
./demo/run_web_demo.sh
```

The single-node sandbox the demo boots only binds loopback, so it does not need
the `NET_ADMIN`/`NET_RAW` capabilities the dev container requests (those are for
CCF's own multi-node/partition tooling).

In a Codespace the URL is **not** `127.0.0.1:8080`. The launcher still prints
`http://127.0.0.1:8080`, but reach it at the forwarded URL instead — open the
**Ports** tab and click the 8080 forward, or use
`https://<codespace-name>-8080.app.github.dev`. The role paths below work the
same way: append them to whichever origin you're using.

## Opening each role

Each role has its own page. Open it directly by URL, or use the nav bar (and the
landing-page cards), whose links carry a `target` per role so each opens in its
own named browser window — handy for placing them side by side and watching the
live event ticker update across all of them at once.

| Role | Path | Local URL |
| ---- | ---- | --------- |
| Landing | `/` | `http://127.0.0.1:8080/` |
| Member | `/member` | `http://127.0.0.1:8080/member` |
| Client | `/client` | `http://127.0.0.1:8080/client` |
| Operator | `/operator` | `http://127.0.0.1:8080/operator` |
| Researcher | `/researcher` | `http://127.0.0.1:8080/researcher` |
| Wall (live feed) | `/wall` | `http://127.0.0.1:8080/wall` |

In a Codespace, swap the `http://127.0.0.1:8080` prefix for your forwarded
origin (e.g. `https://<codespace-name>-8080.app.github.dev/operator`).

## How it works

The browser never talks to the ledger directly: it cannot present the mutual-TLS
client certificates the confidential endpoints require, cannot decode COSE, and
the sandbox private keys must not leave the container. So a small FastAPI backend
is the *real* client — it holds the certs, speaks CBOR/COSE over mutual TLS, and
verifies statements with the `sd_cwt` reference library. The browser talks plain
JSON to that backend and gets live push updates over a WebSocket.

```
 browser windows            FastAPI backend (this app)        CCF node :8000
 client / operator  ──JSON──▶  holds certs, CBOR/COSE   ──mTLS──▶  /app/*
 researcher / member ◀─WS──   sd_cwt offline verifier
```

Role separation is enforced by the backend: operator/member routes use their
client certs, client/researcher routes use none — the same trust model the
ledger itself uses.

## The roles

- **Member** — initialise (or rotate) the issuer signing key. Do this first.
- **Client** — file a report anonymously; get back a redacted token and proof the
  plaintext never appears on the wire.
- **Operator** — browse the ledger, read a report unredacted, release a partial
  field-level disclosure, and file duplicate-proof follow-ups.
- **Researcher** — verify a released disclosure offline against the endorsed
  issuer key; see only what was revealed, with the rest still sealed.

Suggested flow: Member initialises the key → Client submits → Operator discloses
a field → Researcher verifies.

## Files

- [`server.py`](server.py) — FastAPI app: pages, JSON routes, event bus.
- [`ledger_client.py`](ledger_client.py) — the real CCF client + verifier.
- [`events.py`](events.py) — in-process pub/sub for the live WebSocket feed.
- `templates/`, `static/` — the browser UI (no build step).

## Config

Environment variables (the launcher sets sensible defaults):

- `DEMO_URL` — node URL (default `https://127.0.0.1:8000`).
- `DEMO_COMMON_DIR` — sandbox cert directory (default `workspace/sandbox_common`).
- `HOST` / `PORT` — where the web UI listens (default `127.0.0.1:8080`).
