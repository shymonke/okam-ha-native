# O-KAM Native Bridge for Home Assistant

Created and maintained by [shymonke](https://github.com/shymonke).

O-KAM Native Bridge connects an O-KAM Pro camera directly to Home Assistant on
64-bit ARM (`aarch64`) and x86-64 (`amd64`) systems. Live video, snapshots,
camera wake-up, and disconnects are handled by the Home Assistant host.

The project contains both required parts:

- **O-KAM Native Bridge app** — connects to the camera and provides the local
  authenticated media API.
- **O-KAM Native Bridge integration** — creates the Home Assistant camera
  entity, including live view and snapshots.

## Features

- Native operation on `aarch64` and `amd64` with no desktop or emulation layer
- Live H.264 video in Home Assistant, with no transcoding
- **Both lenses of dual-lens cameras**, each as its own camera entity
- Full-resolution JPEG snapshots
- Setup without tokens or URLs: Home Assistant discovers the bridge itself
- One camera connection shared by every simultaneous viewer
- Automatic stream stop and clean disconnect after the last viewer leaves
- Clear setup messages in the app log and as a Home Assistant notification
- No vendor identifiers, account tokens, or passwords exposed by the status API

## Requirements

- A Home Assistant system reporting the `aarch64` or `amd64` architecture
- An O-KAM Pro camera that works in the O-KAM mobile app
- An O-KAM account that can view the cameras; the account may own them or have
  them shared to it. Every camera the account exposes is served.
- HACS for the easiest integration installation, or access to
  `/config/custom_components` for manual installation

The app is published as one multi-architecture image:

| Home Assistant architecture | Typical systems |
| --- | --- |
| `aarch64` | Raspberry Pi 3, 4, or 5 running a 64-bit OS; other 64-bit ARM hosts |
| `amd64` | Intel or AMD mini PCs, servers, and virtual machines |

Raspberry Pi 4 is physically validated. Raspberry Pi 3 is eligible when it is
running a 64-bit Home Assistant installation, but its lower performance has not
been measured. A 32-bit installation cannot install this app. Check the value
shown under **Settings → System → Repairs → System information → Architecture**
if you are unsure.

## Installation

### 1. Check the O-KAM account

Use the normal O-KAM account that can open the camera's live view. It may be
the camera owner account or an account to which cameras were shared. Every
camera the account can see is served, one Home Assistant entity each.

Sign in with that account in the O-KAM mobile app once and confirm that live
view works. Keep its email address and password available for app
configuration.

### 2. Install the O-KAM Native Bridge app

1. In Home Assistant, open **Settings → Apps → App store**.
2. Open the app-store menu (**⋮**) and select **Repositories**.
3. Add this repository:

   ```text
   https://github.com/shymonke/okam-ha-native
   ```

4. Find and install **O-KAM Native Bridge**. Installing takes a few minutes.
5. Open its **Configuration** tab and fill in only these two:

   | Option | What to enter |
   | --- | --- |
   | **O-KAM account email** | Email address of the O-KAM account |
   | **O-KAM account password** | Password of that account |

   Leave everything else as it is. In particular:

   - **Local API token** — leave blank. The app creates a secure token, fills
     it in for you, and hands it to Home Assistant automatically.
   - **VP camera password key** — leave blank; see
     [Newer (VP) cameras](#newer-vp-cameras-the-camera-password-key) below.
   - **Camera alias** — only used when the account has a single camera, for
     example `cabin`.
   - The four **Run … diagnostic** switches — keep them off.

6. Select **Save**, then **Start**. The app also starts automatically with
   Home Assistant.
7. Open the **Log** tab. A working setup shows:

   ```text
   native_loader_ready=true
   account_enumerated=true device_count=1
   bridge_ready=true camera_count=1
   discovery_published=true
   ```

   The counts match the number of cameras on the account.

If something is missing, the log names it, for example
`configuration_required=account_password`, and Home Assistant shows a
notification (bell icon) saying what to fill in. Values are never printed.

### Newer (VP) cameras: the camera password key

Newer O-KAM cameras (VP models, for example dual-lens cameras whose ID starts
with `VE`) receive an automatically generated camera password from the O-KAM
account in scrambled form. Unscrambling it needs a fixed key that lives inside
the official O-KAM PC client, the program file `SuperIPCam.exe`. The key is the
same for everyone, but this project does not copy vendor values, so the app
finds it in your own copy of the client:

1. Get the official O-KAM / VStarcam PC client ("IP Camera Super Client") from
   the vendor, install it on a computer, and locate `SuperIPCam.exe` in its
   installation folder. Only the file is needed; the program does not have to
   run, and the app never runs it.
2. Copy `SuperIPCam.exe` into this app's config folder:

   ```text
   /addon_configs/local_okam_native/
   ```

   (The folder name may start with a different prefix when installed from the
   app store; it ends in `okam_native`.) Use the **Samba share** or **File
   editor / Studio Code Server** app to reach it.
3. Restart the app. The log shows `vp_password_key_search=started` and, after
   up to a minute, `vp_password_key_search=found`. The key is saved privately
   and the file can then be deleted.

How the key is found without being shipped: the app tries every text string in
the client against your own camera's scrambled password. Only the real key
unscrambles it into a valid password (a wrong string passes about one time in a
billion), so no key is stored in this repository.

If you already know the key, you can paste it into **VP camera password key**
instead. Older cameras do not need any of this.

### Camera password

The bridge normally obtains the camera-level password automatically. Only set
`camera_password` when the log reports a camera-authentication failure and the
camera uses a changed local password. It is not the O-KAM account password.

### 3. Install the Home Assistant integration

#### Recommended: HACS

1. Open **HACS** in Home Assistant.
2. Add `https://github.com/shymonke/okam-ha-native` as a custom repository of
   type **Integration**.
3. Find and install **O-KAM Native Bridge**.
4. Restart Home Assistant when HACS asks you to.

#### Manual installation

1. Copy this repository's `custom_components/okam` directory to:

   ```text
   /config/custom_components/okam
   ```

2. Restart Home Assistant.

### 4. Add the camera in Home Assistant

1. Open **Settings → Devices & services**. Under **Discovered**, an
   **O-KAM Native Bridge** card appears once the app is running.
2. Select **Add**, choose the camera, and select **Submit**. No URL or token is
   needed.
3. Optionally pick an area, then finish.

With the alias `cabin`, Home Assistant creates `camera.cabin`. For each further
camera on the account, open the integration and select **Add hub**; the bridge
URL and token are pre-filled, so only the camera ID changes.

**Dual-lens cameras** get one entity per lens: `camera.cabin` for the first
lens and `camera.cabin_lens_2` for the second. The second lens appears
automatically the first time the camera streams (open live view once). Both
entities share a single camera connection.

#### Manual setup for a bridge outside Home Assistant

1. Open **Settings → Devices & services**.
2. Select **Add integration** and search for **O-KAM Native Bridge**.
3. Enter the following values:

   | Field | Value |
   | --- | --- |
   | Bridge URL | `http://HOME_ASSISTANT_LAN_IP:8099` |
   | API token | The **Local API token** shown in the app's configuration |
   | Camera ID | The camera alias, such as `cabin` |
   | Idle timeout | `120` seconds is recommended |
   | Status refresh interval | `900` seconds is recommended |

Use the actual LAN address of Home Assistant, for example
`http://192.168.1.20:8099`. Do not use `localhost`.

## Daily use

Open the camera entity or add it to a dashboard with a camera card. When no one
is watching, the preview shows **Camera sleeping** without connecting. Open
live view to connect; **Camera waking up — please wait 20–30 seconds** is
displayed until video arrives.

Live view uses the camera's native H.264 stream. Multiple viewers, and both
lenses of a dual-lens camera, share the same connection. When the final viewer
closes, the bridge waits for the idle timeout (120 seconds by default), stops
the stream, and disconnects. For continuous recorders such as Frigate, enable
**Keep streams always on** instead.

## Giving someone else access to the video

Give each trusted person or program (for example a developer testing a vision
model) their own **guest token**. Guest tokens can view snapshots and live
video but cannot change any setting, and removing one never affects Home
Assistant.

1. In the app's **Configuration**, under **Guest access tokens**, add an entry
   with a name such as `friend` and leave its token blank. Save and restart the
   app. The log shows `guest_tokens_active=friend` and the generated token
   appears in the entry (eye icon).
2. Give them network access to port 8099 only, without exposing Home Assistant
   to the internet. With Tailscale: install the Tailscale app on Home Assistant,
   share only that machine with them (**Machines → ⋯ → Share**), and add an
   access rule that limits them to port 8099:

   ```json
   {
     "hosts": { "okam-bridge": "HA_TAILSCALE_IP" },
     "acls": [
       { "action": "accept", "src": ["autogroup:member"], "dst": ["*:*"] },
       { "action": "accept", "src": ["friend@example.com"], "dst": ["okam-bridge:8099"] }
     ]
   }
   ```

   Do not use port forwarding or a public tunnel without its own login.
3. They send the token as a header on every request:

   ```text
   Authorization: Bearer <guest token>

   GET http://HOST:8099/api/devices                               camera IDs and lens counts
   GET http://HOST:8099/api/cameras/cabin/snapshot.jpg            JPEG, lens 1
   GET http://HOST:8099/api/cameras/cabin/snapshot.jpg?lens=1     JPEG, lens 2
   GET http://HOST:8099/api/cameras/cabin/stream/source?lens=1    live stream URL, lens 2
   ```

   The returned stream URL already carries a private stream key, so it opens
   directly in VLC, ffmpeg or OpenCV without the header.

To revoke access, delete the entry and restart the app.

## Updating

- Update the **app** from **Settings → Apps**.
- Update the **integration** from HACS.
- Restart Home Assistant after an integration update.

The two components use the same release version.

## Diagnostics

For local command-line access to exposed cameras, see the
[O-KAM CLI guide](docs/cli.md). Besides the bridge commands (device listing,
status, snapshots, idle timeout), the CLI can talk to VP cameras directly:
record per-lens clips, serve a live stream, or watch every lens in the
terminal with `okam tui`.

The app exposes two local status endpoints:

- `http://HOME_ASSISTANT_LAN_IP:8099/health` — service liveness
- `http://HOME_ASSISTANT_LAN_IP:8099/ready` — bridge and stream state

During normal idle operation, `/ready` should report:

```json
{
  "camera_ready": true,
  "phase": "bridge_ready",
  "stream_running": false,
  "stream_viewers": 0
}
```

While Home Assistant is displaying live video, it reports `phase: streaming`,
`stream_running: true`, and at least one viewer.

See [Troubleshooting](docs/troubleshooting.md) for common setup and connection
problems.

## Uninstalling

1. Remove **O-KAM Native Bridge** from **Settings → Devices & services**.
2. Stop and uninstall the **O-KAM Native Bridge** app.
3. Optionally remove the custom repositories from HACS and the app store.
4. Optionally remove the camera from the O-KAM account used by the bridge.

## Security

- Use an O-KAM account that contains only the camera intended for Home Assistant.
- Keep the O-KAM password and local API token private. Hide passwords (eye
  icon) before taking screenshots of the configuration page.
- Do not expose or port-forward TCP port 8099 to the internet.
- Rotate the local API token if it is accidentally disclosed.
- Logs and issue reports must not contain credentials, tokens, or camera IDs.

See [SECURITY.md](SECURITY.md) for the complete security policy.

## Technical overview

The app enumerates the camera through the fixed official account service,
wakes it through the official low-power service, and opens a native P2P
transport. On `aarch64`, a minimal Bionic compatibility layer hosts the official
ARM64 transport library. On `amd64`, a small pure-Python client implements the
same encrypted camera protocol directly. H.264 is forwarded to Home Assistant
without transcoding. FFmpeg is invoked only when a JPEG snapshot is requested.
Required official artifacts are downloaded from their pinned source and
verified before use.

More detail is available in [Architecture](docs/architecture.md).

## Support and license

Open an issue at
[github.com/shymonke/okam-ha-native/issues](https://github.com/shymonke/okam-ha-native/issues)
with the app version, hardware model, Home Assistant version, app log, and
the redacted `/ready` response. Never include passwords, API tokens, or camera
identifiers.

The bridge source is MIT licensed. Vendor components remain subject to their
own terms and are not stored in this repository.
