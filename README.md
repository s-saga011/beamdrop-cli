# beamdrop CLI

Native, high-throughput peer-to-peer file transfer over WebRTC. Bypasses the
browser's SCTP stack to deliver real LAN/WAN speed (tens to hundreds of MB/s
where the Web app is capped around 5–8 MB/s).

Reuses the [beamdrop](https://p2p.draft-publish.com/) signaling server so
links interoperate across senders/receivers.

## One-line install (or auto-update)

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.sh | sh
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1 | iex
```

The installer:
- detects an existing `beamdrop` (skipping download if it's already at the latest tag)
- otherwise drops a single binary at `~/.local/bin/beamdrop` (macOS/Linux) or
  `%USERPROFILE%\.beamdrop\beamdrop.exe` (Windows)
- forwards trailing arguments, so a recipient can install-and-receive in **one** command

```bash
# install or update if needed, then receive
curl -fsSL https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.sh | sh -s -- recv ROOM
```

```powershell
# install or update if needed, then receive
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1))) recv ROOM
```

Same pattern works for `send <file>`. Set `BEAMDROP_FORCE_INSTALL=1` to force a re-download.

## Usage

### Send a file

```bash
beamdrop send path/to/movie.mp4
```

Outputs a share URL like
`https://p2p.draft-publish.com/r/Ab3xK9`. Send that to the receiver.

### Receive

```bash
beamdrop recv https://p2p.draft-publish.com/r/Ab3xK9
# or just the room id:
beamdrop recv Ab3xK9
```

Receiver writes the file to the current working directory.

### Custom signaling server

```bash
beamdrop send big.iso --server https://your.signaling.server
beamdrop recv ROOM    --server https://your.signaling.server
```

## How it works

- Native pion/webrtc WebRTC stack (no Chrome SCTP throttling).
- Uses beamdrop's existing WebSocket signaling for ICE/SDP exchange and
  Cloudflare TURN credentials.
- Single ordered+reliable DataChannel, 256 KB chunks.
- 4-byte big-endian sequence number prefixed to each binary chunk.
- Plain transfer (no app-layer encryption yet — DTLS protects on the wire).
  Encryption parity with the Web client is on the roadmap.

## Speed

| Pair | Throughput |
|---|---|
| Mac CLI ↔ Mac CLI (LAN) | **~36 MB/s** (peak ~57) |
| Browser ↔ Browser (LAN, same hardware) | ~7 MB/s |

## Build from source

```bash
git clone git@github.com:s-saga011/beamdrop-cli.git
cd beamdrop-cli
go build -o beamdrop .
```

## License

MIT.
