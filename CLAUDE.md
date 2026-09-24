# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

`shymonke/okam-ha-native` is a standalone, single-camera O-KAM Pro / CS2 bridge
for Home Assistant. It is an independent project: it is not a fork, it does not
target any upstream pull request, and it does not credit an upstream project.
The MIT `LICENSE` is kept verbatim and authorship must not be misrepresented.

This checkout is the first preview snapshot (`0.1.0-preview1`). It contains two
shipped components that share a release version:

- **Bridge app** (`okam_native_app/`, `src/okam_native/`) — enumerates the
  camera via the official account service, wakes it, opens a native P2P
  transport, and serves an authenticated local media API (H.264 passthrough,
  JPEG snapshots via FFmpeg only on demand).
- **HA integration** (`custom_components/okam/`) — creates the `camera.*`
  entity (live view + snapshots) that talks to the bridge over HTTP.

## Scope and limitations (keep the docs honest)

- Exactly one O-KAM Pro (CS2) camera per account. This is the validated path.
- VP-series cameras may be enumerated by the account service but cannot be
  streamed. They are not supported.
- PTZ (pan/tilt/zoom) and IR / night-vision control are not implemented.
- The validated `ghcr.io/shymonke/okam-ha-native` preview image is published
  with `linux/arm64` and `linux/amd64` manifests, so the app is installable from
  the app store. The image workflow is `workflow_dispatch`-only; keep publication
  manual and republish through it rather than re-enabling a `push` trigger. Keep
  the install-availability and supported-scope statements in `README.md`,
  `okam_native_app/README.md`, and `okam_native_app/DOCS.md` current.

## Working rule for protocol changes

Change one behavior at a time and add a deterministic unit test for every
protocol correction. The amd64 protocol lives in `src/okam_native/cs2.py`
(directory lookup, UDP punching, relay negotiation, packet encryption, reliable
channels, command framing, auth, H.264 parsing) with the helper contract in
`src/okam_native/amd64_helper.py` and entry point
`native/amd64_connect/okam-amd64-connect`. Keep functional CS2 code untouched
unless a change is the explicit task.

## Security / privacy (hard rules)

Never add or commit credentials, camera identifiers, service parameters, IP
addresses, tokens, endpoints, or captured camera payloads — not in code, tests,
docs, logs, or commit messages. Protocol notes may record only sanitized
structure: packet type, channel, sequence, payload length, command ID, response
result, timing, state transitions. `src/okam_native/redaction.py` exists for
this; see `SECURITY.md`.

## Environment & commands

A local virtualenv (`.venv`, Python 3.11+) is expected. Recreate with:

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e '.[test]'
```

Run the test suite (expect 104 passing):

```bash
.venv/Scripts/python.exe -m pytest -q
```

CS2-focused subset (expect 38 passing):

```bash
.venv/Scripts/python.exe -m pytest tests/test_cs2.py -q
```

Optional extras (`pyproject.toml`): `trace` (frida), `inspect`/`test`
(pyelftools). Console script: `okam-acceptance` → `okam_native.acceptance:main`.

## Layout

- `src/okam_native/` — bridge core: `account.py`, `wakeup.py`, `p2p.py`,
  `session.py`, `bridge.py`, `cs2.py`, `amd64_helper.py`, `redaction.py`,
  `acceptance.py`.
- `custom_components/okam/` — HA integration (`camera.py`, `config_flow.py`,
  `coordinator.py`, `api.py`, …).
- `okam_native_app/` — HA add-on packaging: `Dockerfile` (arch-specific final
  stage), `config.yaml`, `app_entrypoint.py`.
- `native/` — C helpers/probes per arch (arm64 hybris, amd64 connect, probes).
- `tools/` — tracing/inspection utilities (frida scripts, SDK fetch/inspect).
- `tests/` — pytest suite. `.github/workflows/` — tests plus a manual
  multi-arch build/publish workflow.

## Before proposing a release

The app version is aligned across `pyproject.toml`, `okam_native_app/config.yaml`,
`custom_components/okam/manifest.json`, and the Dockerfile `BUILD_VERSION`
default. The publish workflow is `workflow_dispatch`-only; keep it manual and do
not re-enable a `push` trigger. A published image must carry both
`linux/amd64` and `linux/arm64` manifests, the aarch64 Raspberry
Pi 4 regression must still pass, and the full unit suite plus CI must be green.
