# Selective Disclosure App

A CCF application (starting from the upstream `basic` sample) for exploring COSE
tokens and selective disclosure. CCF is built **from source** so the framework
itself can be modified.

## Layout
- `third_party/CCF` — CCF as a git submodule, pinned to `ccf-7.0.5`.
- `app/` — the application (`find_package(ccf)` + `add_ccf_app`).
- `docker/` — dev image + build helpers.

## Workflow (edit on host, build in container)
```bash
git submodule update --init --recursive   # first checkout
./docker/build-image.sh                   # build the toolchain image (once)
./docker/dev.sh                           # enter dev container (repo mounted at /workspace)

# Inside the container:
./docker/build-ccf.sh                     # build + install CCF (slow first time)
./docker/build-app.sh                     # build the app against it
```

Build outputs land under the mounted repo (`.ccf-install/`, `*/build/`) so they
persist across container restarts.

## Notes
- All CCF build options are left enabled. Parallelism is throttled in
  `docker/build-ccf.sh` (`NPROC_COMPILE`, `NPROC_LINK`) to avoid OOM on 16 GB.
