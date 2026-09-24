# amd64 transport notes

Development notes for the `amd64` transport used by the O-KAM Native Bridge.
They record how the pure-Python CS2/PPPP client was built and what physical
testing established. No account credentials, camera identifiers, service
parameters, IP addresses, or captured payloads are included.

## Goal

Publish one lightweight Home Assistant app for both supported 64-bit
architectures:

- `aarch64`: the official ARM64 transport library behind a small
  Bionic/`libhybris` compatibility layer.
- `amd64`: a native pure-Python implementation of the same encrypted CS2/PPPP
  UDP transport, with no emulation, Wine, Android, or graphical runtime.

The account API, wake service, bridge HTTP API, snapshots, idle lifecycle, and
Home Assistant custom integration are shared by both.

## Code layout

- `src/okam_native/cs2.py` implements directory lookup, direct UDP punching,
  relay negotiation, packet encryption, reliable data channels, camera command
  framing, authentication, and H.264 frame parsing.
- `src/okam_native/amd64_helper.py` implements the same stdin/stdout helper
  contract used by the ARM64 helper.
- `native/amd64_connect/okam-amd64-connect` is the executable entry point used
  by the amd64 container.
- The app Dockerfile selects an architecture-specific final stage while sharing
  the runtime and minimal FFmpeg build.
- The publish workflow builds `linux/arm64` and `linux/amd64`, then creates the
  versioned and `latest` multi-architecture manifests. It is manual-only in this
  snapshot because no image has been published yet.

## What is verified

- The pure `amd64` helper connects to the physical camera.
- The enumerated credential authenticates on the first attempt over the relay
  session.
- Live-start is acknowledged and channel 1 delivers real H.264, including a
  keyframe.
- Live-stop is sent and the P2P session disconnects cleanly.
- A locally built `linux/amd64` image serves an MPEG-TS stream through the
  bridge HTTP endpoint and produces a full-resolution JPEG snapshot.
- The Home Assistant config flow creates the camera entity; `camera/stream`
  returns an HLS playlist whose segments are real fMP4 media, and the camera
  proxy returns a JPEG.
- A clean `aarch64` image still passes the physical Raspberry Pi 4 stream and
  snapshot regression.

## Transport findings

The camera uses a mixed clear/encrypted CS2 wire format. The packet classes and
recovered cipher vectors are covered by unit tests.

1. The official transport probes the advertised UDP port plus or minus three.
   The pure client uses the same bounded range.
2. A camera command must be written as one atomic DRW channel-0 payload. The
   official API accepts its header and body separately but coalesces them before
   emitting the transport packet.
3. Media requires the relay session. The relay request is addressed to the
   **directory servers**, which answer and then hand over the data session; it
   is never sent to the relay itself. A direct UDP punch yields a session that
   authenticates and acknowledges live-start but never delivers video, so the
   relay-preferring path is the default.
4. Over the relay, the enumerated credential authenticates on the first
   attempt, and live-start is answered with an alternate accepted command.
5. Inbound packets are matched on the peer host, not the exact port, so media
   is not discarded when NAT renumbers the source port. Port drift is counted.
6. `CS2Session.counters` records sanitized packet counts only — no addresses,
   payloads, or credentials. `CS2Session.connect_path` records which branch
   established the peer (`direct-punch`, `direct-accept`, or `relay`).

## Known limitation: connect intermittency

After many sessions in quick succession the relay can stop answering the
handover packet, and connect fails even after several minutes of rest. The
negotiation with the directory servers succeeds and punches are sent, but the
peer never completes the relay handover. During these failures the camera
floods direct-readiness requests, trying to force a direct session.

Two teardown corrections reduced the frequency: every endpoint a session touched
is notified on close, and a declined direct readiness request is acknowledged
without adopting the sender as the session peer. Measured after both changes,
four consecutive stream runs over the relay all succeeded where previously only
the first run after a long idle period did.

The behaviour is not perfect. When it degrades, the signature is that the
enumerated credential is rejected, the empty-password candidate returns a bogus
success, and no media follows. `login_candidate != 0` predicts a session that
will not stream and is a better readiness test than the live-start result.

Product implication: because a camera may need a cool-down between P2P sessions,
the bridge holds one session open and disconnects only after an idle timeout,
rather than reconnecting per request.

## Known follow-ups

Not defects, but rough edges observed while testing.

### A bridge restart invalidates a live view already open

`CameraBridge` generates a fresh stream token on every process start, and Home
Assistant caches the stream URL inside the `Stream` object built for the entity.
After the bridge restarts, the cached URL keeps the old token and the stream
worker fails with `401 Unauthorized` until the config entry is reloaded or a new
stream is created. Two ways to fix, neither attempted yet:

- Derive the stream token from a value that survives a restart, so a cached URL
  stays valid.
- Have the integration notice the failure and call the stream's
  `update_source()` with a freshly fetched URL.

### The camera entity state lags the bridge

The coordinator polls bridge status on its own interval, so `camera.*` can still
read `idle` while media is actively flowing. Snapshots and live view both work in
that window, so this is cosmetic, but it makes the entity state a poor signal for
automations that want to know whether the camera is streaming.

## Test status

- The complete unit test suite passes.
- The CS2-focused subset passes.
- `git diff --check` passes.
- Python compilation across source, integration, app, tests, and tools passes.
- Temporary development probes and build directories are intentionally not part
  of the repository.
