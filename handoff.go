package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

// handoff carries what a restarted sender needs to keep serving the same
// share link to a different receiver.
type handoff struct {
	room  string
	key   []byte
	token string // our signaling peer token (keeps our peerId)
	peer  string // the new receiver's peerId

	// Sender takeover (beamdrop://HOST/s/... link, see sendlink.go): we are a
	// NEW sender joining a room a web page was serving. No peer id is known
	// up front; chunk and name keep the meta identical to the page's so a
	// receiver that is mid-file resumes instead of starting over.
	takeover bool
	chunk    int64
	name     string

	// rejoin: our own connections to the receiver broke for good and ICE
	// restarts did not bring them back (see rejoinAsNewSender). Handled like
	// a takeover - of ourselves.
	rejoin bool
}

// pendingTakeover is set by `beamdrop open` for a /s/ link, in-process.
var pendingTakeover *handoff

const handoffEnv = "BEAMDROP_HANDOFF"

// takeHandoff reads and clears the handoff left by the previous incarnation.
func takeHandoff() *handoff {
	if h := pendingTakeover; h != nil {
		pendingTakeover = nil
		return h
	}
	v := os.Getenv(handoffEnv)
	if v == "" {
		return nil
	}
	os.Unsetenv(handoffEnv)
	f := strings.Split(v, "\n")
	if len(f) != 4 {
		return nil
	}
	key, err := b64URL.DecodeString(f[1])
	if err != nil || len(key) != 32 {
		return nil
	}
	if chunk, ok := strings.CutPrefix(f[3], "rejoin:"); ok && f[2] == "" {
		n, _ := strconv.ParseInt(chunk, 10, 64)
		return &handoff{room: f[0], key: key, takeover: true, rejoin: true, chunk: n}
	}
	return &handoff{room: f[0], key: key, token: f[2], peer: f[3]}
}

// handoffToNewReceiver restarts the send for a receiver that replaced the
// one we were serving. The transfer state (bitmaps, congestion control,
// PeerConnections, a dozen goroutines) all belongs to the old receiver, so
// rather than untangle it we re-execute ourselves: same argv, same room, key
// and signaling identity, and a clean slate for everything else.
func handoffToNewReceiver(h handoff, ws *safeWS, pcs []*webrtc.PeerConnection) {
	fmt.Fprintf(os.Stderr, "\n[handoff] a new receiver joined - restarting the transfer for it\n")
	env := append(os.Environ(), handoffEnv+"="+strings.Join(
		[]string{h.room, b64URL.EncodeToString(h.key), h.token, h.peer}, "\n"))
	ws.close()
	for _, pc := range pcs {
		if pc != nil {
			_ = pc.Close()
		}
	}
	if err := reexec(env); err != nil {
		die(fmt.Errorf("restart for new receiver failed: %w", err))
	}
}

// rejoinAsNewSender is the last resort when the connections to the receiver
// are broken and ICE restarts do not revive them (seen with a phone on a VPN:
// we would report "connected" again, the phone never did, and the transfer
// sat at 72% until the 3 minute abort). We leave the room and come back as a
// brand-new sender: the receiver's page drops its dead connections, keeps
// what it has, and its bitmap makes us resume where it stopped - the same
// path as taking a send over from a web page.
func rejoinAsNewSender(room string, key []byte, chunk int64, ws *safeWS, pcs []*webrtc.PeerConnection) {
	fmt.Fprintf(os.Stderr, "\n[stall] the connection did not come back - reconnecting from scratch (the transfer resumes where it stopped)\n")
	env := append(os.Environ(), handoffEnv+"="+strings.Join(
		[]string{room, b64URL.EncodeToString(key), "", "rejoin:" + strconv.FormatInt(chunk, 10)}, "\n"))
	_ = ws.write(sigMsg{Type: "leave"}) // frees our slot at once (no reconnect grace)
	time.Sleep(300 * time.Millisecond)
	ws.close()
	for _, pc := range pcs {
		if pc != nil {
			_ = pc.Close()
		}
	}
	if err := reexec(env); err != nil {
		die(fmt.Errorf("restart failed: %w", err))
	}
}
