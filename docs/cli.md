# O-KAM CLI guide

Install the command-line extras into a Python 3.11+ environment:

```
pip install "okam-native[cli,vp]"
```

## Account login

Direct commands talk to VP cameras through your O-KAM account. Save the login
once in the system keyring (Windows Credential Manager on Windows):

```
okam login --vp-salt-file PATH   # checks the login, then saves it
okam logout                      # removes the saved login
```

`OKAM_EMAIL`, `OKAM_PASSWORD` and `OKAM_VP_PASSWORD_SALT` override the saved
values. Without either, commands prompt; the password is never shown or stored
in files.

## Direct camera commands

| Command | What it does |
|---|---|
| `okam cameras` | List cameras on the account (`--show-secrets` prints VP inputs) |
| `okam clip CAMERA OUT.mp4 --seconds N` | Record every lens to `OUT-lens0.mp4`, `OUT-lens1.mp4`, ... (`--lens N` for one) |
| `okam grab CAMERA OUT.jpg [--lens N]` | Save one JPEG (needs ffmpeg) |
| `okam serve CAMERA [--lens N] [--listen HOST:PORT]` | Serve live H.264 for VLC or go2rtc |
| `okam tui CAMERA [--quality low/medium/high]` | Watch every lens live in the terminal |

Clips start timing at the first frame, begin each lens at a keyframe and are
decoded before success is reported. Connection failures are retried.

### Terminal viewer keys

`r` record, `s` snapshot, `1`/`2` one lens, `b` both, `v` preview quality,
`c` reconnect now, `q` quit. Recordings and snapshots go to
`./okam-captures` (or `--output-dir`). Windows Terminal 1.22+ shows real
images (sixel); other terminals fall back to block characters.

## Bridge commands

With the Home Assistant app running, `okam devices`, `okam status`,
`okam snapshot` and `okam configure` use the bridge API (`--bridge URL`,
token in `OKAM_API_TOKEN`).
