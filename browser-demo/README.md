# Browser-local demo

This static demo reproduces the Researcher, Disclosure Authority, and Independent Verifier workflow without a backend. It is designed for GitHub Pages.

## Run locally

From the repository root:

```bash
python3 -m http.server 8008
```

Open <http://127.0.0.1:8008/browser-demo/> and select **Open all roles**.

## Browser architecture

- WebCrypto signs researcher statements, authority endorsements, local transparency receipts, and key-binding tokens.
- IndexedDB stores session-scoped keys, reports, receipts, deliveries, and disclosures.
- BroadcastChannel notifies role tabs when a report or disclosure is available.
- Web Locks serialize initialization and append-only log updates.
- A signed Merkle inclusion proof binds each registration to the browser-local log.

## Limitations

This is a local simulation, not Microsoft Signing Transparency or a deployed SCITT service. All tabs share one browser origin and are not independent security boundaries. Data is isolated to one browser profile and is not shared across users or devices. The demo does not provide CCF governance, consensus, durable service storage, or hardware-backed guarantees.

The demo requires a current browser with WebCrypto, IndexedDB, BroadcastChannel, and Web Locks support.

## Self-test

With the local server running, open <http://127.0.0.1:8008/browser-demo/tests/>. A passing result exercises a two-entry log, selective disclosure, all six verification checks, wrong-audience rejection, tamper rejection, and IndexedDB persistence.
