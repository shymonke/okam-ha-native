# Security policy

## Supported versions

Security fixes are provided for the latest published release. The current
release is the independent `0.1.0-preview1` preview snapshot; its prebuilt
multi-architecture image is published to GitHub Container Registry at
`ghcr.io/shymonke/okam-ha-native`.

## Supported scope

Only the single-camera O-KAM Pro / CS2 bridge is supported. VP-series cameras
may be enumerated but cannot be streamed, and PTZ and IR control are not
implemented. Security reports are accepted for the supported path only.

## Reporting a vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/shymonke/okam-ha-native/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability.

## Credential safety

- Use an O-KAM account containing only the camera intended for Home Assistant.
- Use a unique random local API token of at least 16 characters.
- Never post account names, passwords, API tokens, camera identifiers, packet
  captures, media, or unredacted logs.
- Rotate a password or token immediately if it may have been disclosed.
- Supply secrets only through Home Assistant app options.

## Network safety

- Keep TCP port 8099 on the trusted local network.
- Do not port-forward the bridge or expose it through a public reverse proxy.
- Camera API routes require bearer authentication. The liveness and readiness
  routes intentionally expose only non-secret operational state.

## Supply chain

Vendor artifacts are downloaded from a fixed official source and verified
against pinned checksums before use. They are not committed to this repository
or embedded in the published source archive.
