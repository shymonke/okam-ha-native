# O-KAM Native Bridge

Connect one O-KAM Pro (CS2) camera directly to Home Assistant on `aarch64` and
`amd64` systems. The app provides native live video, full-resolution snapshots,
automatic wake-up, shared viewing, and idle disconnect.

**Preview snapshot.** This is `0.1.0-preview1`. The prebuilt
`ghcr.io/shymonke/okam-ha-native` image has not been published yet, so this app
cannot be installed from the app store until that image exists.

## Scope and limitations

- Exactly one O-KAM Pro (CS2) camera per account, owned or shared.
- VP-series cameras may be enumerated by the account service but cannot be
  streamed.
- PTZ (pan/tilt/zoom) and IR / night-vision control are not implemented.

The matching Home Assistant integration is included in the same repository.
See the **Documentation** tab for the complete setup guide.
