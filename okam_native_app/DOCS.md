# O-KAM Native Bridge

O-KAM Native Bridge connects your O-KAM Pro cameras directly to Home Assistant
on `aarch64` and `amd64` systems. It provides live H.264 video, JPEG snapshots,
automatic camera wake-up, shared viewing, and automatic idle disconnect, with
one Home Assistant camera entity per camera on the account.

## Before configuring the app

Use the O-KAM account that can view the cameras. This can be the normal
camera-owner account or an account to which cameras were shared. Every camera
the account exposes is served. Sign in with that account in the O-KAM app once
and confirm that live view works.

## Configuration

| Option | Description |
| --- | --- |
| `account_username` | Email address of the O-KAM account |
| `account_password` | Password of the O-KAM account |
| `camera_password` | Optional camera-level password override; normally leave blank |
| `api_token` | Leave blank; the app creates one, shows it here (eye icon) and passes it to Home Assistant automatically |
| `camera_id` | Alias used when the account exposes a lone camera, for example `cabin`; ignored when several are present |
| `idle_timeout_seconds` | Delay before disconnecting after the final viewer closes; `120` is recommended |
| `vp_password_salt` | Normally leave blank: put the O-KAM PC client `SuperIPCam.exe` in this app's config folder and the key is found automatically (VP cameras only) |
| `guest_tokens` | Named read-only tokens for people or programs outside Home Assistant; leave the token blank and it is generated. Delete an entry to revoke it |
| `always_on` | Keep each camera streaming without viewers and reconnect automatically; enable for continuous recorders such as Frigate. Ignores the idle delay |

The API token is not an O-KAM credential. When it is blank the app generates a
secure token, stores it privately, and hands it to Home Assistant through
Supervisor discovery. Set it only for a bridge used outside Home Assistant.

The app normally obtains the camera-level credential automatically and has a
compatibility fallback for accounts that omit it. Set `camera_password` only
when camera authentication fails and the camera uses a changed local password.
It is not the O-KAM account password.

### Newer (VP) cameras

VP cameras (for example dual-lens models with IDs starting `VE`) need a
camera-password key that lives in the official O-KAM PC client. Copy the
client's `SuperIPCam.exe` into `/addon_configs/<prefix>_okam_native/` (via the
Samba share or File editor app) and restart. The log shows
`vp_password_key_search=found` and the key is saved privately; the file can
then be deleted. The app only reads the file, never runs it, and finds the key
by testing candidates against your own camera's scrambled password.

### Setup messages

A missing setting is named in the log (for example
`configuration_required=account_password`) and shown as a Home Assistant
notification. Values are never printed.

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

The counts equal the number of cameras on the account; a two-camera account
reports `device_count=2` and `camera_count=2`.

The readiness page is available at:

```text
http://HOME_ASSISTANT_LAN_IP:8099/ready
```

It should report `camera_ready: true` and `phase: bridge_ready` while idle.

## Home Assistant integration

Install **O-KAM Native Bridge** from HACS using
`https://github.com/shymonke/okam-ha-native` as a custom integration repository.
Restart Home Assistant. With the app running, **O-KAM Native Bridge** appears
under **Settings → Devices & services → Discovered**; select **Add** and choose
the camera. No URL or token is needed.

For a bridge outside Home Assistant, add the integration manually and use:

- Bridge URL: `http://HOME_ASSISTANT_LAN_IP:8099`
- API token: the `api_token` set on that bridge
- Camera ID: the alias of the camera to add, such as `cabin`
- Idle timeout: `120`

Do not use `localhost` for the bridge URL. With the `cabin` alias, a new
installation creates `camera.cabin` unless that entity ID is already occupied.

### Several cameras

The bridge serves every camera on the account. Add the integration once per
camera: each entry names one `Camera ID` and creates one camera entity.

A lone camera keeps the `camera_id` alias configured in the app. When the
account exposes several cameras the aliases are derived from the camera names,
so read the exact values from the bridge's `/api/devices` endpoint before
adding each entry.

### Dual-lens cameras

Each lens becomes its own entity, for example `camera.cabin` and
`camera.cabin_lens_2`. The second lens appears automatically after the camera
first streams (open live view once). Both share one camera connection.

## Operation

A sleeping camera displays a sleeping image without waking it. Open live view
to wake the camera; a waking-up image remains visible until video arrives,
which commonly takes 20–30 seconds. Multiple viewers share one camera
connection. After the final viewer closes, the bridge stops and disconnects
after the configured idle timeout. The 120-second default allows brief page
changes and reloads to reuse the warm connection. Installations created before
version 1.1.1 retain their selected value; use the integration's **Configure**
action to change an older 30-second value to 120 seconds.

Do not expose TCP port 8099 to the internet. See the repository
[README](https://github.com/shymonke/okam-ha-native#readme) and
[troubleshooting guide](https://github.com/shymonke/okam-ha-native/blob/main/docs/troubleshooting.md)
for complete installation and support information.
