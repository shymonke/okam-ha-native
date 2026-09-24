# Changelog

## 0.1.0-preview1

First independent preview snapshot of the standalone `shymonke/okam-ha-native`
bridge. This snapshot is the validated single-camera O-KAM Pro / CS2 bridge.

Validated:

- One O-KAM Pro (CS2) camera per account, owned or shared.
- Live H.264 passthrough and JPEG snapshots on `aarch64` and `amd64`.
- Low-power wake-up, shared viewing, and clean idle disconnect.
- Native transport on both architectures: the official ARM64 library behind a
  minimal Bionic compatibility layer on `aarch64`, and a pure-Python encrypted
  CS2/PPPP UDP client on `amd64`.
- MPEG-TS live output that Home Assistant's stream worker can serve as HLS, and
  live-view priming from cached parameter sets and the newest keyframe.
- A multi-architecture image built from one Dockerfile with architecture-correct
  labels.

Known limitations:

- VP-series cameras may be enumerated by the account service but cannot be
  streamed.
- PTZ (pan/tilt/zoom) and IR / night-vision control are not implemented.
- Only one camera per account is supported.
- The prebuilt `ghcr.io/shymonke/okam-ha-native` image has not been published
  yet, so the app is not installable from the app store until that image exists.
  See `README.md` for the current installation status.

Inherited behaviour carried into this snapshot:

- The camera password option is genuinely optional; the bridge falls back to the
  enumerated credential, then to the camera's common initial value.
- Accounts that omit the camera-level credential are handled, with an optional
  local `camera_password` override for changed device passwords.
- The configured camera alias becomes the exact suggested entity ID on a fresh
  Home Assistant installation, for example `camera.cabin`.
- Live media is reached over the camera's relay session, with the relay request
  addressed to the directory servers.
- Every endpoint a session touched is notified on close, and a declined direct
  readiness request is acknowledged, so a camera does not hold a stale binding.
- Relay media is accepted when NAT renumbers the peer's source port.
- An abruptly closed client connection is no longer reported as a crash.
- The idle disconnect default is 120 seconds, and the effective timeout is
  reported in camera and readiness status.
- Protocol-vector, wire-format, reliable-channel, H.264, helper-contract,
  metadata, architecture-selection, relay-negotiation, session-teardown, and
  live-view priming tests are included.
