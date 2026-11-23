package main

import (
	"fmt"
	"os"
	"strings"

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
