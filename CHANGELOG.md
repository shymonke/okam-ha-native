# Changelog

## 1.3.0

- Supports newer O-KAM VP cameras (for example dual-lens `VE` models) over the
  vendor relay, natively on `amd64` and `aarch64`.
- Serves both lenses of dual-lens cameras from one camera connection; each lens
  is its own camera entity (`camera.<id>` and `camera.<id>_lens_2`).
- Setup without tokens or URLs: the app generates its API token and Home
  Assistant discovers the bridge (**Settings → Devices & services →
  Discovered**). The token is shown in the app's masked **Local API token**
  field for sharing.
- Finds the VP camera-password key automatically from the user's own copy of
  the official PC client (`SuperIPCam.exe` in the app's config folder); the
  manual option still overrides.
- Adds named, read-only **guest tokens** for sharing camera access with people
  or programs outside Home Assistant; deleting an entry revokes it.
- Names missing settings in the log, the status and a Home Assistant
  notification, never their values. No option is required at the Supervisor
  level any more, so a missing value can no longer make the Supervisor echo
  the submitted configuration.
- Ships an integration icon and titles the discovery card.

### Also in this release

- Serves every camera the configured O-KAM account can see, one Home Assistant
  camera entity per camera. Previously the account had to expose exactly one
  camera and the bridge refused any other account.
- Derives a stable alias per camera from the camera name when several are
  present, disambiguating collisions. A lone camera keeps the configured
  `camera_id`, so existing installations and their entity identifiers are
  unchanged.
- Adds a camera registry and per-camera stream token, so a token issued for one
  camera cannot open another camera's stream.
- Allows the Home Assistant integration to be added once per camera against the
  same bridge URL. The config entry is now unique per camera, not per bridge.

## 1.2.1

- Shows the release notes in the app update dialog. The supervisor reads a
  changelog from the app directory, so updating previously reported that none
  was found.

## 1.2.0

- Adds native `amd64` support alongside the existing `aarch64` runtime.
- Implements the camera's encrypted CS2/PPPP UDP transport and command framing
  directly for x86-64 Home Assistant hosts.
- Publishes one prebuilt multi-architecture image with architecture-correct
  Home Assistant labels.
- Keeps the account, wake, bridge API, streaming, snapshot, and lifecycle logic
  shared across both architectures.
- Stops reporting a disconnected client as a crash. The supervisor polls the
  bridge and closes connections abruptly, which filled the app log with
  ConnectionResetError tracebacks for normal behaviour (issue #5).
- Makes the camera password option genuinely optional. The bridge already fell
  back to the enumerated credential when it was empty, but the add-on schema
  still required a value, and its null default kept the key present and
  invalid, so the options could not be saved without one and no placeholder
  was safe (issue #5).
- Handles accounts that omit the camera-level credential, with an optional
  local camera-password override for changed device passwords.
- Uses the configured camera alias as the exact suggested entity ID on a fresh
  Home Assistant installation, for example `camera.cabin`.
- Reaches the camera's media over its relay session. A direct UDP punch yields
  a session that authenticates and acknowledges live-start but never delivers
  video, and it previously hid the relay path by winning the race.
- Addresses the relay request to the directory servers rather than to the relay
  itself, which is what makes the relay rendezvous complete.
- Notifies every endpoint a session touched when closing, and acknowledges a
  declined direct readiness request, so a camera does not hold a stale binding
  that blocks the next connection.
- Accepts relay media when NAT renumbers the peer's source port, which
  previously discarded the entire media channel while control traffic
  continued to work.
- Serves the live stream as MPEG-TS with timestamps, so Home Assistant's
  stream worker can build HLS. A raw elementary stream was rejected with
  "No dts in consecutive packets", so live view never played while snapshots
  kept working.
- Starts a newly opened live view on a decodable boundary by caching the
  stream's parameter sets and newest keyframe. Opening a second view of an
  already-streaming camera no longer waits for the camera's next keyframe.
- Adds protocol-vector, wire-format, reliable-channel, H.264, helper-contract,
  metadata, architecture-selection, relay-negotiation, session-teardown, and
  live-view priming tests.

## 1.1.1

- Refreshes the Home Assistant camera image as soon as native H.264 media
  becomes ready, preventing the waking-up image from remaining on screen.
- Reuses the last successful snapshot if a later still-image request briefly
  fails.
- Increases the default idle disconnect delay from 30 seconds to 120 seconds so
  normal page changes can reuse the warm camera connection.
- Reports the effective runtime idle timeout in camera and readiness status.

## 1.1.0

- Accepts the normal camera-owner account as well as an account with a shared
  camera, provided the account exposes exactly one camera.
- Makes the app available to all 64-bit ARM (`aarch64`) Home Assistant systems.
- Shows informative sleeping and waking-up images while live video is inactive
  or the battery camera is waking.
- Reports the distinct `camera_waking` phase and native-media readiness.
- Clarifies hardware compatibility and stream wake behavior throughout the
  installation documentation.

## 1.0.0

- Provides native ARM64 live video and snapshots for O-KAM Pro cameras.
- Supports 64-bit Home Assistant OS on Raspberry Pi 4 and Raspberry Pi 5.
- Adds automatic camera wake-up and clean idle disconnect.
- Shares one native stream between simultaneous Home Assistant viewers.
- Includes the HACS-compatible O-KAM Native Bridge integration.
- Adds authenticated local configuration, status, snapshot, and stream APIs.
- Enables automatic app startup and production release metadata.
- Documents complete installation, operation, updating, diagnostics,
  troubleshooting, security, and removal procedures.
