# O-KAM Native Bridge

O-KAM Native Bridge connects one O-KAM Pro (CS2) camera directly to Home
Assistant on `aarch64` and `amd64` systems. It provides live H.264 video, JPEG
snapshots, automatic camera wake-up, shared viewing, and automatic idle
disconnect.

**Preview image available.** This is `0.1.0-preview1`. The validated
single-camera O-KAM Pro / CS2 preview image is published at
`ghcr.io/shymonke/okam-ha-native` for `aarch64` and `amd64`, so the app can be
installed from the app store.

## Supported scope

- Exactly one O-KAM Pro (CS2) camera per account. The account may own the camera
  or have it shared to it.
- VP-series cameras may be enumerated by the account service, but they cannot
  be streamed. They are not supported.
- PTZ (pan/tilt/zoom) and IR / night-vision control are not implemented.
- More than one camera per account is not supported.

## Before configuring the app

Use an O-KAM account that can view exactly one camera. This can be the normal
camera-owner account or an account to which the camera was shared. Sign in with
that account in the O-KAM app once and confirm that live view works.

## Configuration

| Option | Description |
| --- | --- |
| `account_username` | Email address of the O-KAM account |
| `account_password` | Password of the O-KAM account |
| `camera_password` | Optional camera-level password override; normally leave blank |
| `api_token` | A random local secret of at least 16 characters chosen by you |
| `camera_id` | Home Assistant camera alias, for example `cabin` |
| `idle_timeout_seconds` | Delay before disconnecting after the final viewer closes; `120` is recommended |

The API token is not an O-KAM credential. Create a new random value and enter
the identical value when adding the Home Assistant integration.

The app normally obtains the camera-level credential automatically and has a
compatibility fallback for accounts that omit it. Set `camera_password` only
when camera authentication fails and the camera uses a changed local password.
It is not the O-KAM account password.

Leave `run_connect_test`, `run_auth_test`, `run_stream_test`, and
`run_snapshot_test` disabled during normal operation. They are bounded
diagnostic checks intended only for troubleshooting.

## Starting the app

Save the configuration and start the app. Automatic startup is enabled by
default. A successful startup log contains:

```text
native_loader_ready=true
account_enumerated=true device_count=1
bridge_ready=true camera_count=1
```

The readiness page is available at:

```text
http://HOME_ASSISTANT_LAN_IP:8099/ready
```

It should report `camera_ready: true` and `phase: bridge_ready` while idle.

## Home Assistant integration

Install **O-KAM Native Bridge** from HACS using
`https://github.com/shymonke/okam-ha-native` as a custom integration repository.
Restart Home Assistant, then add the integration from **Settings → Devices &
services**.

Use:

- Bridge URL: `http://HOME_ASSISTANT_LAN_IP:8099`
- API token: the value configured above
- Camera ID: the configured alias, such as `cabin`
- Idle timeout: `120`

Do not use `localhost` for the bridge URL. With the `cabin` alias, a new
installation creates `camera.cabin` unless that entity ID is already occupied.

## Operation

A sleeping camera displays a sleeping image without waking it. Open live view
to wake the camera; a waking-up image remains visible until video arrives,
which commonly takes 20–30 seconds. Multiple viewers share one camera
connection. After the final viewer closes, the bridge stops and disconnects
after the configured idle timeout. The 120-second default allows brief page
changes and reloads to reuse the warm connection.

Do not expose TCP port 8099 to the internet. See the repository
[README](https://github.com/shymonke/okam-ha-native#readme) and
[troubleshooting guide](https://github.com/shymonke/okam-ha-native/blob/main/docs/troubleshooting.md)
for complete installation and support information.
