// beamdrop CLI — pion/webrtc-based file transfer.
//
// Implements beamdrop's v3 protocol (browser-compatible) plus optional
// resume + SHA-256 verification extensions:
//
//   - Reuses beamdrop signaling: POST /api/rooms, WS /ws/{room},
//     pcIdx-tagged offer/answer/ice messages.
//   - 4 RTCPeerConnections; each carries one unordered/maxRetransmits:0 data DC
//     (label "file-N", N=0..3). pc[0] also carries one reliable+ordered control
//     DC (label "control") for meta / done / bitmap / complete JSON messages.
//   - AES-256-GCM per chunk. IV = [0,0,0,0] || BE64(seq). Key shared in the
//     URL fragment (#k=base64url) so it never reaches the signaling server.
//   - Wire format for chunks: [4-byte BE seq][AES-GCM ciphertext+tag].
//   - 16 KB plaintext chunks (matches browser SCTP fragment expectations).
//   - Receiver reports a bitmap on control every 200 ms; sender retransmits
//     missing seqs in passes (round-robin across DCs) until receiver sends
//     {"type":"complete"} or the pass limit is hit.
//
// Optional extensions (CLI implements; browser implements where feasible):
//   - meta.prefixHash: SHA-256 hex of the first 4096 bytes of the source file.
//     Receivers that find a matching .part file can resume safely.
//   - "resume" (recv→send): one-shot control message after meta carrying the
//     receiver's initial bitmap (chunks it already has on disk). The sender
//     skips those seqs in Phase 1 so resume only retransmits missing chunks.
//   - done.fileHash: SHA-256 hex of the entire plaintext file. The receiver
//     verifies after all chunks reassemble. AES-GCM already authenticates
//     each chunk individually, so this is belt-and-braces; senders MAY omit
//     it (browser sender currently does, since Web Crypto has no streaming
//     SHA-256 API).
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mdp/qrterminal/v3"
	"github.com/pion/webrtc/v4"
)

// Version is set via -ldflags "-X main.Version=v0.2.0" at build time;
// the const fallback keeps `beamdrop --version` honest when run from `go run`.
var Version = "v0.4.0"

const (
	chunkSize           = 16 * 1024
	bufferedHigh        = 4 * 1024 * 1024
	bufferedLow         = 1 * 1024 * 1024
	numPCs              = 4
	seqHeaderBytes      = 4
	ivLength            = 12
	prefixHashSize      = 4096
	bitmapInterval        = 200 * time.Millisecond
	retransmitInterval    = 250 * time.Millisecond
	maxRetransmitInterval = 8 * time.Second // back off up to this when receiver isn't keeping up
	maxRetransmitPasses   = 60
	retransmitBatchLimit  = 2000 // chunks per pass — keep small so receiver can drain between passes
	retransmitBatchMin    = 200  // floor when we shrink the batch under loss
	stagnantPassThreshold = 12   // ~3s of "no progress" passes before bailing
	relayInflightWindow = 1000 // chunks (16MB) — relay-only cap, since pion bufferedAmount under-reports on TCP/TLS

	// Phase 0 probe + adaptive throttle params
	resumeWaitTimeout   = 1500 * time.Millisecond
	protocolVersion     = 3
	defaultServer       = "https://p2p.draft-publish.com"
	stallTimeout        = 30 * time.Second // abort send if bytesPushed doesn't move for this long
	statsInterval       = 2 * time.Second  // sender->server stats cadence
)

// ============================================================================
// Helpers: bitmap / base64url / AES-GCM / share URL
// ============================================================================

// Bitmap layout matches the browser: one bit per seq, LSB-first within byte:
//   bm[idx>>3] |= 1 << (idx & 7)
func newBitmap(numBits int) []byte {
	if numBits <= 0 {
		return nil
	}
	return make([]byte, (numBits+7)/8)
}

func setBit(bm []byte, idx int) {
	bm[idx>>3] |= 1 << uint(idx&7)
}

func getBit(bm []byte, idx int) bool {
	if bm == nil || idx>>3 >= len(bm) {
		return false
	}
	return (bm[idx>>3]>>uint(idx&7))&1 == 1
}

func countSetBits(bm []byte) int {
	c := 0
	for _, b := range bm {
		c += bits.OnesCount8(b)
	}
	return c
}

var b64URL = base64.RawURLEncoding

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// chunkIV builds the per-chunk IV. Browser writes:
//   new DataView(iv.buffer).setBigUint64(4, BigInt(seq))
// — leading 4 zero bytes followed by big-endian uint64(seq).
func chunkIV(seq uint32) []byte {
	iv := make([]byte, ivLength)
	binary.BigEndian.PutUint64(iv[4:], uint64(seq))
	return iv
}

func encryptChunk(aead cipher.AEAD, pt []byte, seq uint32) []byte {
	return aead.Seal(nil, chunkIV(seq), pt, nil)
}

func decryptChunk(aead cipher.AEAD, ct []byte, seq uint32) ([]byte, error) {
	return aead.Open(nil, chunkIV(seq), ct, nil)
}

type shareTarget struct {
	server string
	room   string
	keyB64 string
	relay  bool
}

// parseFragmentParams returns each `name=value` pair found in the fragment.
func parseFragmentParams(frag string) map[string]string {
	out := map[string]string{}
	if frag == "" {
		return out
	}
	for _, kv := range strings.Split(frag, "&") {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

func parseShareTarget(arg, fallbackServer string) (shareTarget, error) {
	out := shareTarget{server: fallbackServer}
	applyFrag := func(frag string) {
		params := parseFragmentParams(frag)
		out.keyB64 = params["k"]
		if v := params["relay"]; v == "1" || v == "true" {
			out.relay = true
		}
	}
	if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
		u, err := url.Parse(arg)
		if err != nil {
			return out, fmt.Errorf("parse url: %w", err)
		}
		out.server = u.Scheme + "://" + u.Host
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] != "r" {
			return out, fmt.Errorf("URL must be of form server/r/ROOM[#k=KEY]")
		}
		out.room = parts[1]
		applyFrag(u.Fragment)
		return out, nil
	}
	if hashIdx := strings.Index(arg, "#"); hashIdx >= 0 {
		out.room = arg[:hashIdx]
		applyFrag(arg[hashIdx+1:])
		return out, nil
	}
	out.room = arg
	return out, nil
}

// hashFilePrefix returns hex-encoded SHA-256 of the first prefixHashSize
// bytes of file (or the whole file if smaller). Resume safety check.
func hashFilePrefix(path string, total int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	n := int64(prefixHashSize)
	if total < n {
		n = total
	}
	h := sha256.New()
	if _, err := io.CopyN(h, f, n); err != nil && err != io.EOF {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashFileFull(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ============================================================================
// Signaling
// ============================================================================

type sigMsg struct {
	Type      string                     `json:"type"`
	From      string                     `json:"from,omitempty"`
	To        string                     `json:"to,omitempty"`
	PeerID    string                     `json:"peerId,omitempty"`
	Role      string                     `json:"role,omitempty"`
	Reason    string                     `json:"reason,omitempty"`
	SDP       *webrtc.SessionDescription `json:"sdp,omitempty"`
	Candidate *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
	PcIdx     *int                       `json:"pcIdx,omitempty"`
}

func toWSURL(server, room string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", err
	}
	scheme := "wss"
	if u.Scheme == "http" {
		scheme = "ws"
	}
	return fmt.Sprintf("%s://%s/ws/%s", scheme, u.Host, room), nil
}

func dialSignaling(server, room string) (*websocket.Conn, error) {
	wsURL, err := toWSURL(server, room)
	if err != nil {
		return nil, err
	}
	c, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	return c, err
}

func createRoom(server string) (string, error) {
	resp, err := http.Post(server+"/api/rooms", "application/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create-room status %d", resp.StatusCode)
	}
	var r struct {
		Room string `json:"room"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.Room == "" {
		return "", fmt.Errorf("server returned empty room id")
	}
	return r.Room, nil
}

func fetchICE(server string) ([]webrtc.ICEServer, error) {
	resp, err := http.Get(server + "/api/turn")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		IceServers []struct {
			URLs       any    `json:"urls"`
			Username   string `json:"username,omitempty"`
			Credential string `json:"credential,omitempty"`
		} `json:"iceServers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	out := make([]webrtc.ICEServer, 0, len(r.IceServers))
	for _, s := range r.IceServers {
		var urls []string
		switch v := s.URLs.(type) {
		case string:
			urls = []string{v}
		case []any:
			for _, x := range v {
				if str, ok := x.(string); ok {
					urls = append(urls, str)
				}
			}
		}
		out = append(out, webrtc.ICEServer{
			URLs:       urls,
			Username:   s.Username,
			Credential: s.Credential,
		})
	}
	return out, nil
}

// safeWS wraps a *websocket.Conn with a mutex; gorilla/websocket forbids
// concurrent writers and pion ICE callbacks fire on background goroutines.
type safeWS struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (s *safeWS) write(m sigMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteJSON(m)
}

// writeRaw sends a pre-marshalled JSON payload (e.g. stats reports that
// don't fit the sigMsg shape).
func (s *safeWS) writeRaw(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(websocket.TextMessage, b)
}

// ============================================================================
// Main entry
// ============================================================================

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cleanupStaleBinary()
	switch os.Args[1] {
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
	case "update":
		runUpdate()
	case "--version", "-v", "version":
		fmt.Println(Version)
		return
	case "--help", "-h", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `beamdrop CLI — high-speed P2P file transfer

Usage:
  beamdrop send <file> [--server URL] [--relay]
  beamdrop recv <url>             # share URL printed by 'send' (must include #k=KEY)
  beamdrop recv <room#k=KEY> [--server URL] [--relay]
  beamdrop update                 # download the latest release in place
  beamdrop --version              # print current version

Flags:
  --server URL  override signaling server (default: https://p2p.draft-publish.com)
  --relay       force-route through Cloudflare TURN over TLS:443. Bypasses
                cellular carrier UDP/P2P shaping. Use when a mobile-network
                transfer crawls; otherwise leave off.
`)
	os.Exit(1)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

// flags is the parsed result of parseFlags.
type flags struct {
	server string
	relay  bool
	pos    []string
}

func parseFlags(args []string) flags {
	out := flags{server: defaultServer}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--server":
			i++
			if i < len(args) {
				out.server = args[i]
			}
		case "--relay":
			out.relay = true
		default:
			out.pos = append(out.pos, a)
		}
	}
	return out
}

// newRelayAPI returns a *webrtc.API whose ICE agent gathers TCP candidates.
// pion v4 defaults to UDP-only network types, which silently drops every
// turn:host:port?transport=tcp / turns:host:443 URL on the floor (the
// candidate pool ends up empty and ICE fails with "no candidate pairs").
func newRelayAPI() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.SetNetworkTypes([]webrtc.NetworkType{
		webrtc.NetworkTypeUDP4,
		webrtc.NetworkTypeUDP6,
		webrtc.NetworkTypeTCP4,
		webrtc.NetworkTypeTCP6,
	})
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

// filterRelayTLS narrows iceServers to only the TLS:443 turns: URL,
// dropping STUN and other TURN candidates. Used together with
// ICETransportPolicyRelay to force every ICE pair through TLS/443/TCP —
// the path that survives mobile-carrier UDP/P2P shaping (mimics HTTPS).
func filterRelayTLS(iceServers []webrtc.ICEServer) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, 0, len(iceServers))
	for _, s := range iceServers {
		var keep []string
		for _, u := range s.URLs {
			lu := strings.ToLower(u)
			if strings.HasPrefix(lu, "turns:") &&
				strings.Contains(lu, ":443") &&
				strings.Contains(lu, "transport=tcp") {
				keep = append(keep, u)
			}
		}
		if len(keep) > 0 {
			out = append(out, webrtc.ICEServer{
				URLs:       keep,
				Username:   s.Username,
				Credential: s.Credential,
			})
		}
	}
	return out
}

func ptr[T any](v T) *T { return &v }

// ============================================================================
// Sender
// ============================================================================

func runSend(args []string) {
	checkForUpdate()
	fl := parseFlags(args)
	if len(fl.pos) < 1 {
		die(fmt.Errorf("usage: beamdrop send <file>"))
	}
	server := fl.server
	path := fl.pos[0]

	stat, err := os.Stat(path)
	if err != nil {
		die(err)
	}
	totalBytes := stat.Size()
	expectedChunks := int((totalBytes + chunkSize - 1) / chunkSize)
	if expectedChunks == 0 {
		expectedChunks = 1
	}

	fmt.Printf("File: %s (%s, %d chunks)\n", filepath.Base(path), formatBytes(totalBytes), expectedChunks)

	prefixHash, err := hashFilePrefix(path, totalBytes)
	if err != nil {
		die(fmt.Errorf("prefix hash: %w", err))
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		die(fmt.Errorf("generate key: %w", err))
	}
	keyB64 := b64URL.EncodeToString(keyBytes)
	aead, err := newAEAD(keyBytes)
	if err != nil {
		die(err)
	}

	room, err := createRoom(server)
	if err != nil {
		die(fmt.Errorf("createRoom: %w", err))
	}
	shareURL := fmt.Sprintf("%s/r/%s#k=%s", server, room, keyB64)
	if fl.relay {
		// Carry the relay hint in the URL so the receiver also force-routes
		// through TURN/TLS:443. Otherwise ICE on the receiver's side might
		// pick a faster (UDP) candidate that the carrier then shapes anyway.
		shareURL += "&relay=1"
	}
	printShareInstructions(room, shareURL)

	iceServers, err := fetchICE(server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: fetchICE failed: %v (using STUN only)\n", err)
		iceServers = []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	}
	pcConfig := webrtc.Configuration{ICEServers: iceServers}
	pcAPI := webrtc.NewAPI() // default UDP-only — fine for direct/UDP-TURN paths
	if fl.relay {
		filtered := filterRelayTLS(iceServers)
		if len(filtered) == 0 {
			die(fmt.Errorf("--relay requested but no TLS:443 TURN URL available from %s/api/turn", server))
		}
		pcConfig.ICEServers = filtered
		pcConfig.ICETransportPolicy = webrtc.ICETransportPolicyRelay
		pcAPI = newRelayAPI() // pion v4 won't gather TCP candidates without this
		fmt.Println("Relay mode: forcing all traffic through TURN over TLS:443")
	}

	wsConn, err := dialSignaling(server, room)
	if err != nil {
		die(fmt.Errorf("dial signaling: %w", err))
	}
	defer wsConn.Close()
	ws := &safeWS{conn: wsConn}

	// In --relay mode use a single PC. Allocating four parallel TURN
	// allocations over TLS:443 from the same mobile IP appears to hit
	// per-IP simultaneous-allocation limits at Cloudflare or in Chrome
	// itself, with most allocations silently failing — so the DCs never
	// open and the receiver tab sits at 'シグナリングサーバーに接続中'.
	// Reliability path doesn't benefit from 4 parallel SCTPs the way
	// datagram does (TCP serializes anyway), so 1 PC is plenty.
	effectivePCs := numPCs
	if fl.relay {
		effectivePCs = 1
	}
	pcs := make([]*webrtc.PeerConnection, effectivePCs)
	for i := 0; i < effectivePCs; i++ {
		pc, err := pcAPI.NewPeerConnection(pcConfig)
		if err != nil {
			die(err)
		}
		pcs[i] = pc
		defer pc.Close()
	}

	var remotePeerID atomic.Value

	for i, pc := range pcs {
		idx := i
		pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				fmt.Fprintf(os.Stderr, "[pc%d] ICE gathering done\n", idx)
				return
			}
			ci := c.ToJSON()
			fmt.Fprintf(os.Stderr, "[pc%d] local cand: %s\n", idx, ci.Candidate)
			rid, _ := remotePeerID.Load().(string)
			if rid == "" {
				return
			}
			_ = ws.write(sigMsg{Type: "ice", To: rid, Candidate: &ci, PcIdx: ptr(idx)})
		})
		pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
			fmt.Fprintf(os.Stderr, "[pc%d] ICE state: %s\n", idx, s.String())
		})
		pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
			fmt.Fprintf(os.Stderr, "[pc%d] PC state: %s\n", idx, s.String())
		})
	}

	dataDCs := make([]*webrtc.DataChannel, effectivePCs)
	bufLow := make([]chan struct{}, effectivePCs)
	// In --relay mode (TURN over TLS:443), the underlying transport is
	// already TCP/TLS and reliable end-to-end; running datagram-mode data
	// DCs on top just adds an unnecessary application-layer retransmit
	// loop that fights SCTP's own congestion control. Make them reliable+
	// ordered so SCTP handles loss directly.
	for i, pc := range pcs {
		idx := i
		dcInit := &webrtc.DataChannelInit{}
		if fl.relay {
			dcInit.Ordered = ptr(true)
			// MaxRetransmits left nil = full reliability
		} else {
			dcInit.Ordered = ptr(false)
			dcInit.MaxRetransmits = ptr(uint16(0))
		}
		dc, err := pc.CreateDataChannel(fmt.Sprintf("file-%d", idx), dcInit)
		if err != nil {
			die(err)
		}
		dc.SetBufferedAmountLowThreshold(bufferedLow)
		ch := make(chan struct{}, 1)
		bufLow[idx] = ch
		dc.OnBufferedAmountLow(func() {
			select {
			case ch <- struct{}{}:
			default:
			}
		})
		dataDCs[idx] = dc
	}
	controlDC, err := pcs[0].CreateDataChannel("control", &webrtc.DataChannelInit{Ordered: ptr(true)})
	if err != nil {
		die(err)
	}

	// retransmit DC: reliable + ordered (no MaxRetransmits / MaxPacketLifeTime).
	// Phase 2 retransmits flow over this DC instead of round-robining across
	// the four datagram-mode file-N DCs. On lossy links (mobile cellular
	// observed at ~80% packet loss) datagram retransmits compound the loss
	// and the bitmap-driven repeat-send blows up bandwidth use; letting SCTP
	// retry on the wire converges far faster. Phase 1 stays on the file-N
	// DCs for max throughput on healthy links.
	retransmitDC, err := pcs[0].CreateDataChannel("retransmit", &webrtc.DataChannelInit{Ordered: ptr(true)})
	if err != nil {
		die(err)
	}
	retransmitDC.SetBufferedAmountLowThreshold(bufferedLow)
	retransmitBufLow := make(chan struct{}, 1)
	retransmitDC.OnBufferedAmountLow(func() {
		select {
		case retransmitBufLow <- struct{}{}:
		default:
		}
	})

	totalDCs := effectivePCs + 2 // file-N × effectivePCs + 1 control + 1 retransmit
	openCh := make(chan struct{}, totalDCs)
	for _, dc := range dataDCs {
		dc.OnOpen(func() { openCh <- struct{}{} })
	}
	controlDC.OnOpen(func() { openCh <- struct{}{} })
	retransmitDC.OnOpen(func() { openCh <- struct{}{} })

	var (
		recvBitmapMu  sync.Mutex
		recvBitmap    []byte
		recvBitmapVer int64
	)
	var transferComplete atomic.Bool
	var bytesPushed atomic.Int64

	resumeBitmapCh := make(chan []byte, 1)
	var resumeDelivered atomic.Bool

	controlDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			return
		}
		var m struct {
			Type     string `json:"type"`
			Version  int64  `json:"version"`
			Received int    `json:"received"`
			Data     string `json:"data"`
		}
		if err := json.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		switch m.Type {
		case "resume":
			if resumeDelivered.Swap(true) {
				return
			}
			bm, derr := b64URL.DecodeString(m.Data)
			if derr != nil {
				return
			}
			select {
			case resumeBitmapCh <- bm:
			default:
			}
		case "bitmap":
			recvBitmapMu.Lock()
			defer recvBitmapMu.Unlock()
			if m.Version <= recvBitmapVer {
				return
			}
			bm, derr := b64URL.DecodeString(m.Data)
			if derr != nil {
				return
			}
			recvBitmap = bm
			recvBitmapVer = m.Version
			// Treat a fully-set bitmap as proof of completion. The
			// receiver's explicit {type:"complete"} can be delayed by
			// OPFS finalize (worker write queue drain on slow NAND) or
			// lost if the control DC has issues, so don't depend on it
			// alone — the bitmap is the truth.
			if countSetBits(bm) >= expectedChunks {
				transferComplete.Store(true)
			}
		case "complete":
			transferComplete.Store(true)
		}
	})

	wsErr := make(chan error, 1)
	go func() {
		for {
			var msg sigMsg
			if err := wsConn.ReadJSON(&msg); err != nil {
				select {
				case wsErr <- err:
				default:
				}
				return
			}
			idx := 0
			if msg.PcIdx != nil {
				idx = *msg.PcIdx
			}
			if idx < 0 || idx >= effectivePCs {
				idx = 0
			}
			fmt.Fprintf(os.Stderr, "[ws] recv type=%s peer=%s pcIdx=%d\n", msg.Type, msg.PeerID, idx)
			switch msg.Type {
			case "joined":
			case "peer-joined":
				fmt.Fprintf(os.Stderr, "[ws] peer-joined → creating offer for %d pc(s)\n", len(pcs))
				remotePeerID.Store(msg.PeerID)
				for i, pc := range pcs {
					pcIdx := i
					p := pc
					go func() {
						offer, err := p.CreateOffer(nil)
						if err != nil {
							fmt.Fprintf(os.Stderr, "[pc%d] CreateOffer error: %v\n", pcIdx, err)
							return
						}
						if err := p.SetLocalDescription(offer); err != nil {
							fmt.Fprintf(os.Stderr, "[pc%d] SetLocalDescription error: %v\n", pcIdx, err)
							return
						}
						rid, _ := remotePeerID.Load().(string)
						fmt.Fprintf(os.Stderr, "[pc%d] sending offer to %s\n", pcIdx, rid)
						_ = ws.write(sigMsg{Type: "offer", To: rid, SDP: &offer, PcIdx: ptr(pcIdx)})
					}()
				}
			case "answer":
				if msg.SDP != nil && pcs[idx] != nil {
					_ = pcs[idx].SetRemoteDescription(*msg.SDP)
				}
			case "ice":
				if msg.Candidate != nil && pcs[idx] != nil {
					_ = pcs[idx].AddICECandidate(*msg.Candidate)
				}
			case "peer-left":
				if !transferComplete.Load() {
					select {
					case wsErr <- fmt.Errorf("receiver disconnected"):
					default:
					}
					return
				}
			case "error":
				select {
				case wsErr <- fmt.Errorf("signaling error: %s", msg.Reason):
				default:
				}
				return
			}
		}
	}()

	fmt.Println("Waiting for receiver...")
	opened := 0
	openTimeout := time.NewTimer(10 * time.Minute)
	defer openTimeout.Stop()
	for opened < totalDCs {
		select {
		case <-openCh:
			opened++
		case err := <-wsErr:
			die(err)
		case <-openTimeout.C:
			die(fmt.Errorf("timeout waiting for receiver to connect"))
		}
	}
	fmt.Println("Connected, starting transfer.")

	mime := "application/octet-stream"
	metaJSON, _ := json.Marshal(map[string]any{
		"type":            "meta",
		"name":            filepath.Base(path),
		"size":            totalBytes,
		"mime":            mime,
		"chunkSize":       chunkSize,
		"totalChunks":     expectedChunks,
		"protocolVersion": protocolVersion,
		"prefixHash":      prefixHash,
	})
	if err := controlDC.SendText(string(metaJSON)); err != nil {
		die(fmt.Errorf("send meta: %w", err))
	}

	// Wait briefly for the receiver to send a "resume" message with its
	// initial bitmap. If they don't, treat as full transfer.
	var resumeBitmap []byte
	select {
	case bm := <-resumeBitmapCh:
		resumeBitmap = bm
		setCount := countSetBits(resumeBitmap)
		if setCount > 0 {
			fmt.Printf("Receiver already has %d/%d chunks — resuming transfer\n", setCount, expectedChunks)
		}
	case <-time.After(resumeWaitTimeout):
		// Fresh transfer (receiver doesn't support resume or has nothing).
	}

	sendStart := time.Now()
	var lastReportMu sync.Mutex
	lastReport := sendStart
	var lastPushed int64

	// abortSig closes when the send is forcibly aborted (stall watchdog or
	// explicit error). Goroutines waiting on DC drains, channel sends, etc.,
	// must include this in their selects so they can unwind cleanly.
	abortSig := make(chan struct{})
	var abortOnce sync.Once
	var abortReason atomic.Value
	abort := func(reason string) {
		abortOnce.Do(func() {
			abortReason.Store(reason)
			close(abortSig)
		})
	}

	// Stall watchdog: if bytesPushed doesn't move for stallTimeout, give up.
	// This catches the case where pion's SCTP buffer wedges (e.g. mobile
	// receiver Wi-Fi went idle) so we don't hang the user's terminal forever.
	go func() {
		var last int64 = -1
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		stalledSince := time.Time{}
		for {
			select {
			case <-abortSig:
				return
			case <-ticker.C:
			}
			if transferComplete.Load() {
				return
			}
			cur := bytesPushed.Load()
			if cur == last && cur > 0 {
				if stalledSince.IsZero() {
					stalledSince = time.Now()
				} else if time.Since(stalledSince) >= stallTimeout {
					abort(fmt.Sprintf("no progress for %s", stallTimeout))
					return
				}
			} else {
				stalledSince = time.Time{}
			}
			last = cur
		}
	}()

	// Sender stats reporter: every statsInterval, push our perspective to the
	// signaling server so it shows up in `journalctl -u beamdrop`. Mirrors
	// what the browser sender already does.
	go func() {
		ticker := time.NewTicker(statsInterval)
		defer ticker.Stop()
		var lastBytes int64
		lastTime := time.Now()
		for {
			select {
			case <-abortSig:
				return
			case <-ticker.C:
			}
			if transferComplete.Load() {
				return
			}
			cur := bytesPushed.Load()
			now := time.Now()
			dt := now.Sub(lastTime).Seconds()
			bps := 0.0
			if dt > 0 {
				bps = float64(cur-lastBytes) / dt
			}
			lastBytes = cur
			lastTime = now
			states := make([]string, len(pcs))
			for i, pc := range pcs {
				if pc != nil {
					states[i] = pc.ConnectionState().String()
				} else {
					states[i] = "nil"
				}
			}
			payload, _ := json.Marshal(map[string]any{
				"type":     "stats",
				"role":     "sender",
				"bytes":    cur,
				"total":    totalBytes,
				"speed":    int64(bps),
				"pcStates": states,
			})
			_ = ws.writeRaw(payload)
		}
	}()

	sendChunk := func(dc *webrtc.DataChannel, ch chan struct{}, seq uint32, plaintext []byte) error {
		ct := encryptChunk(aead, plaintext, seq)
		out := make([]byte, seqHeaderBytes+len(ct))
		binary.BigEndian.PutUint32(out[:seqHeaderBytes], seq)
		copy(out[seqHeaderBytes:], ct)
		for dc.BufferedAmount() > bufferedHigh {
			if transferComplete.Load() {
				return nil
			}
			select {
			case <-ch:
			case <-abortSig:
				return io.EOF
			case <-time.After(500 * time.Millisecond):
			}
		}
		if err := dc.Send(out); err != nil {
			return err
		}
		bytesPushed.Add(int64(len(plaintext)))

		now := time.Now()
		lastReportMu.Lock()
		shouldReport := now.Sub(lastReport) > 500*time.Millisecond
		var pushed, lastP int64
		var dt float64
		if shouldReport {
			pushed = bytesPushed.Load()
			lastP = lastPushed
			dt = now.Sub(lastReport).Seconds()
			lastReport = now
			lastPushed = pushed
		}
		lastReportMu.Unlock()
		if shouldReport {
			// True receiver-side progress comes from the receiver's bitmap;
			// bytesPushed counts every send including retransmits and can
			// run well past totalBytes during Phase 2.
			recvBitmapMu.Lock()
			rb := recvBitmap
			recvBitmapMu.Unlock()
			var ackedBytes int64
			var pct float64
			if rb != nil {
				acked := int64(countSetBits(rb))
				ackedBytes = acked * chunkSize
				if ackedBytes > totalBytes {
					ackedBytes = totalBytes
				}
				if totalBytes > 0 {
					pct = float64(ackedBytes) / float64(totalBytes) * 100
				} else {
					pct = 100
				}
			} else {
				ackedBytes = pushed
				if ackedBytes > totalBytes {
					ackedBytes = totalBytes
				}
				if totalBytes > 0 {
					pct = float64(ackedBytes) / float64(totalBytes) * 100
				} else {
					pct = 100
				}
			}
			rate := float64(pushed-lastP) / dt / 1024 / 1024
			extra := ""
			if pushed > totalBytes {
				extra = fmt.Sprintf("  pushed %s", formatBytes(pushed))
			}
			fmt.Printf("\r  %s %5.1f%%  %s/%s  %.1f MB/s%s   ",
				progressBar(pct, 30), pct, formatBytes(ackedBytes), formatBytes(totalBytes), rate, extra)
		}
		return nil
	}

	type chunkData struct {
		seq uint32
		pt  []byte
	}

	// Phase 1: producer reads file sequentially (so we can compute fileHash
	// on the fly), dispatches chunks to a fan-out channel that the workers
	// consume. Resume-bitmap-acked chunks are skipped (not enqueued, but
	// they are still hashed so the final fileHash covers the whole file).
	chunks := make(chan chunkData, 64)
	var producerErr atomic.Value
	var fileHash atomic.Value

	go func() {
		defer close(chunks)
		f, err := os.Open(path)
		if err != nil {
			producerErr.Store(err)
			return
		}
		defer f.Close()
		hasher := sha256.New()
		buf := make([]byte, chunkSize)
		seq := uint32(0)
		for {
			if transferComplete.Load() {
				break
			}
			select {
			case <-abortSig:
				return
			default:
			}
			n, rerr := io.ReadFull(f, buf)
			if n > 0 {
				hasher.Write(buf[:n])
				if !getBit(resumeBitmap, int(seq)) {
					ptCopy := make([]byte, n)
					copy(ptCopy, buf[:n])
					select {
					case chunks <- chunkData{seq: seq, pt: ptCopy}:
					case <-abortSig:
						return
					}
				}
				seq++
			}
			if rerr == io.EOF {
				break
			}
			if rerr == io.ErrUnexpectedEOF {
				break
			}
			if rerr != nil {
				producerErr.Store(rerr)
				return
			}
		}
		fileHash.Store(hex.EncodeToString(hasher.Sum(nil)))
	}()

	sentBitmap := newBitmap(expectedChunks)
	var sentMu sync.Mutex

	// In --relay (reliable+TCP/TLS) mode, pion's BufferedAmount() doesn't
	// reflect the underlying TCP/TURN/recv-side queue depth, so the
	// bufferedHigh-based throttle in sendChunk fires almost never and the
	// 4 workers dump megabytes into downstream buffers in seconds (which
	// then triggers carrier congestion, the 'starts fast, dies fast'
	// cellular pattern). Bound it with a bitmap-derived window — same
	// idea as TCP's send window. Only enable on relay; on direct UDP path
	// pion's SCTP-level bufferedAmount throttle in sendChunk is sufficient.
	waitInflight := func(seq uint32) {
		if !fl.relay {
			return
		}
		for {
			if transferComplete.Load() {
				return
			}
			recvBitmapMu.Lock()
			rb := recvBitmap
			recvBitmapMu.Unlock()
			ackedCount := 0
			if rb != nil {
				ackedCount = countSetBits(rb)
			}
			if int(seq)-ackedCount < relayInflightWindow {
				return
			}
			select {
			case <-abortSig:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < effectivePCs; i++ {
		wg.Add(1)
		idx := i
		go func() {
			defer wg.Done()
			dc := dataDCs[idx]
			ch := bufLow[idx]
			for cd := range chunks {
				if transferComplete.Load() {
					return
				}
				waitInflight(cd.seq)
				if err := sendChunk(dc, ch, cd.seq, cd.pt); err != nil {
					return
				}
				sentMu.Lock()
				setBit(sentBitmap, int(cd.seq))
				sentMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if v := producerErr.Load(); v != nil {
		die(fmt.Errorf("read file: %w", v.(error)))
	}

	// If watchdog or anything else fired the abort, bail loudly. Sending a
	// final "abort" on the control DC tells the receiver it can stop waiting.
	select {
	case <-abortSig:
		reason, _ := abortReason.Load().(string)
		if reason == "" {
			reason = "unknown"
		}
		fmt.Fprintln(os.Stderr)
		ab, _ := json.Marshal(map[string]any{"type": "abort", "reason": reason})
		_ = controlDC.SendText(string(ab))
		die(fmt.Errorf("transfer aborted: %s (try again — if it keeps happening, check WiFi or use a wired connection)", reason))
	default:
	}

	// Phase 1 done — tell receiver and include fileHash for end-to-end verify.
	finalHash, _ := fileHash.Load().(string)
	doneMsg := map[string]any{"type": "done"}
	if finalHash != "" {
		doneMsg["fileHash"] = finalHash
	}
	doneJSON, _ := json.Marshal(doneMsg)
	_ = controlDC.SendText(string(doneJSON))

	// Phase 2: bitmap-driven retransmit.
	//
	// We retransmit in *small* batches (retransmitBatchLimit chunks per pass)
	// so the receiver can drain its decrypt+store queue and refresh its
	// bitmap between passes. Otherwise — observed in v0.2.0 — the sender
	// floods the receiver with all "missing" chunks, the bitmap stays stale
	// for seconds, and the next pass repeats almost the same set, ballooning
	// total bytes pushed to many multiples of the file size.
	//
	// Pass termination rules:
	//   - We give up after maxRetransmitPasses regardless.
	//   - We also give up after stagnantPassThreshold consecutive passes
	//     where the receiver's bitmap shows zero progress (so we don't
	//     hammer a permanently-broken DC for minutes).
	// Adaptive interval + batch size: when the receiver's bitmap doesn't
	// advance much between passes (delivery ratio < 10%), exponentially
	// back off the wait time and shrink the batch — classic congestion
	// avoidance, mirrors what TCP does on RTO. When the receiver catches
	// up (delivery ratio > 50%), reset to base. This stops the retransmit
	// storm where, on lossy links, our own resends compound the loss and
	// fight SCTP's congestion control instead of working with it.
	pass := 0
	stagnant := 0
	prevReceivedBits := 0
	prevAttempted := 0
	curInterval := retransmitInterval
	curBatchLimit := retransmitBatchLimit
	for pass < maxRetransmitPasses && !transferComplete.Load() {
		select {
		case err := <-wsErr:
			die(err)
		case <-abortSig:
			reason, _ := abortReason.Load().(string)
			ab, _ := json.Marshal(map[string]any{"type": "abort", "reason": reason})
			_ = controlDC.SendText(string(ab))
			die(fmt.Errorf("transfer aborted during retransmit: %s", reason))
		case <-time.After(curInterval):
		}
		if transferComplete.Load() {
			break
		}
		recvBitmapMu.Lock()
		bm := recvBitmap
		recvBitmapMu.Unlock()
		if bm == nil {
			continue
		}
		curReceivedBits := countSetBits(bm)

		// Adjust pacing based on the last pass's effective delivery ratio.
		if prevAttempted > 0 {
			landed := curReceivedBits - prevReceivedBits
			if landed < 0 {
				landed = 0
			}
			ratio := float64(landed) / float64(prevAttempted)
			if ratio < 0.1 {
				// Almost nothing landed — back off.
				curInterval *= 2
				if curInterval > maxRetransmitInterval {
					curInterval = maxRetransmitInterval
				}
				curBatchLimit = curBatchLimit / 2
				if curBatchLimit < retransmitBatchMin {
					curBatchLimit = retransmitBatchMin
				}
			} else if ratio > 0.5 {
				// Receiver is keeping up — return to base pacing.
				curInterval = retransmitInterval
				curBatchLimit = retransmitBatchLimit
			}
		}

		var missing []uint32
		for s := 0; s < expectedChunks; s++ {
			if !getBit(bm, s) {
				missing = append(missing, uint32(s))
				if len(missing) >= curBatchLimit {
					break
				}
			}
		}
		if len(missing) == 0 {
			prevAttempted = 0
			prevReceivedBits = curReceivedBits
			continue
		}
		// Stagnation tracking.
		if curReceivedBits <= prevReceivedBits {
			stagnant++
			if stagnant >= stagnantPassThreshold {
				ab, _ := json.Marshal(map[string]any{"type": "abort", "reason": "no receiver progress for too many retransmit passes"})
				_ = controlDC.SendText(string(ab))
				die(fmt.Errorf("retransmit stagnated: receiver bitmap unchanged for %d passes (still %d/%d chunks)", stagnant, curReceivedBits, expectedChunks))
			}
		} else {
			stagnant = 0
		}
		prevReceivedBits = curReceivedBits
		prevAttempted = len(missing)
		pass++
		fmt.Printf("\n  retransmit pass %d: %d missing (rcv has %d/%d, batch=%d, wait=%s)\n",
			pass, len(missing), curReceivedBits, expectedChunks, curBatchLimit, curInterval)
		f, err := os.Open(path)
		if err != nil {
			die(fmt.Errorf("reopen for retransmit: %w", err))
		}
		for _, s := range missing {
			if transferComplete.Load() {
				break
			}
			offset := int64(s) * chunkSize
			size := int64(chunkSize)
			if offset+size > totalBytes {
				size = totalBytes - offset
			}
			if size <= 0 {
				continue
			}
			pt := make([]byte, size)
			if _, err := f.ReadAt(pt, offset); err != nil && err != io.EOF {
				f.Close()
				die(fmt.Errorf("readat seq=%d: %w", s, err))
			}
			// Send retransmits through the dedicated reliable DC. SCTP's
			// own retransmit handles wire loss; we don't need to re-queue
			// from this end, just push once and trust the lower layer.
			if err := sendChunk(retransmitDC, retransmitBufLow, s, pt); err != nil {
				break
			}
		}
		f.Close()
	}

	// Drain remaining DC buffers so the wire delivery completes. Include
	// the retransmit DC — its reliable mode means lingering bytes are
	// still being acked by SCTP and we want them to land before exit.
	drainStart := time.Now()
	for {
		any := false
		for _, dc := range dataDCs {
			if dc.BufferedAmount() > 0 {
				any = true
				break
			}
		}
		if !any && retransmitDC.BufferedAmount() > 0 {
			any = true
		}
		if !any || time.Since(drainStart) > 10*time.Second {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !transferComplete.Load() {
		select {
		case <-time.After(15 * time.Second):
		}
	}
	if !transferComplete.Load() {
		fmt.Fprintln(os.Stderr)
		die(fmt.Errorf("retransmit limit reached or timeout — receiver did not confirm completion"))
	}

	// Land the progress bar on 100% before printing Done — without this,
	// the bar can be stuck at e.g. 99.1% if the last sendChunk update
	// happened just before the receiver's "complete" landed.
	fmt.Printf("\r  %s 100.0%%  %s/%s                                              \n",
		progressBar(100, 30), formatBytes(totalBytes), formatBytes(totalBytes))

	elapsed := time.Since(sendStart)
	pushed := bytesPushed.Load()
	rate := float64(totalBytes) / elapsed.Seconds() / 1024 / 1024
	fmt.Printf("Done: %s in %s (%.1f MB/s, pushed %s incl. retransmits)\n",
		formatBytes(totalBytes), elapsed.Round(time.Millisecond), rate, formatBytes(pushed))
}

// ============================================================================
// Receiver
// ============================================================================

func runRecv(args []string) {
	checkForUpdate()
	fl := parseFlags(args)
	if len(fl.pos) < 1 {
		die(fmt.Errorf("usage: beamdrop recv <url-or-room>"))
	}
	server := fl.server
	target := fl.pos[0]

	st, err := parseShareTarget(target, server)
	if err != nil {
		die(err)
	}
	if st.server != "" {
		server = st.server
	}
	room := st.room
	if room == "" {
		die(fmt.Errorf("could not parse room id from %q", target))
	}
	if st.keyB64 == "" {
		die(fmt.Errorf("share target is missing the encryption key (#k=KEY). Ask the sender for the full URL printed by 'beamdrop send'."))
	}
	keyBytes, err := b64URL.DecodeString(st.keyB64)
	if err != nil {
		die(fmt.Errorf("decode key: %w", err))
	}
	if len(keyBytes) != 32 {
		die(fmt.Errorf("key must be 256 bits, got %d", len(keyBytes)*8))
	}
	aead, err := newAEAD(keyBytes)
	if err != nil {
		die(err)
	}

	iceServers, err := fetchICE(server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: fetchICE failed: %v\n", err)
		iceServers = []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	}
	relayOn := fl.relay || st.relay
	pcConfig := webrtc.Configuration{ICEServers: iceServers}
	pcAPI := webrtc.NewAPI()
	if relayOn {
		filtered := filterRelayTLS(iceServers)
		if len(filtered) == 0 {
			die(fmt.Errorf("relay requested but no TLS:443 TURN URL available from %s/api/turn", server))
		}
		pcConfig.ICEServers = filtered
		pcConfig.ICETransportPolicy = webrtc.ICETransportPolicyRelay
		pcAPI = newRelayAPI() // pion v4 needs TCP NetworkTypes for turns: candidates
		fmt.Println("Relay mode: forcing all traffic through TURN over TLS:443")
	}

	wsConn, err := dialSignaling(server, room)
	if err != nil {
		die(fmt.Errorf("dial signaling: %w", err))
	}
	defer wsConn.Close()
	ws := &safeWS{conn: wsConn}

	pcs := make([]*webrtc.PeerConnection, numPCs)
	var pcsMu sync.Mutex
	var remotePeerID atomic.Value
	defer func() {
		pcsMu.Lock()
		defer pcsMu.Unlock()
		for _, pc := range pcs {
			if pc != nil {
				_ = pc.Close()
			}
		}
	}()

	var (
		stMu          sync.Mutex
		gotMeta       bool
		metaName      string
		metaSize      int64
		metaChunkSize int64
		metaChunks    int
		metaFileHash  string
		outFile       *os.File
		recvBitmap    []byte
		receivedCount int
		receivedBytes int64
		startT        time.Time
		finished      bool
		lastReport    time.Time
		lastReceived  int64
		expectedHash  string
	)
	type pendingChunk struct {
		seq uint32
		pt  []byte
	}
	var pending []pendingChunk

	transferDone := make(chan error, 1)
	var controlDC atomic.Value

	storeChunk := func(seq uint32, pt []byte) bool {
		if outFile == nil || recvBitmap == nil {
			return false
		}
		if int(seq) >= metaChunks {
			return false
		}
		if getBit(recvBitmap, int(seq)) {
			return false
		}
		offset := int64(seq) * metaChunkSize
		if _, err := outFile.WriteAt(pt, offset); err != nil {
			return false
		}
		setBit(recvBitmap, int(seq))
		receivedCount++
		receivedBytes += int64(len(pt))
		return true
	}

	finishIfComplete := func() {
		if finished || !gotMeta || outFile == nil {
			return
		}
		if receivedCount < metaChunks {
			return
		}
		finished = true
		_ = outFile.Sync()
		_ = outFile.Close()
		outFile = nil

		// Land the progress bar on 100% — the per-chunk Printf is throttled
		// to 500ms and may have last drawn at e.g. 94% when the final batch
		// of chunks landed in one tick.
		fmt.Printf("\r  %s 100.0%%  %s/%s                                              \n",
			progressBar(100, 30), formatBytes(metaSize), formatBytes(metaSize))

		partPath := metaName + ".part"
		verifyMsg := ""
		if expectedHash != "" {
			fmt.Printf("Verifying SHA-256...\n")
			got, herr := hashFileFull(partPath)
			if herr != nil {
				fmt.Fprintf(os.Stderr, "warn: hash %s: %v\n", partPath, herr)
			} else if got != expectedHash {
				select {
				case transferDone <- fmt.Errorf("checksum mismatch: expected %s, got %s — partial kept at %s",
					shortHash(expectedHash), shortHash(got), partPath):
				default:
				}
				return
			} else {
				verifyMsg = " (SHA-256 verified)"
			}
		}

		_ = os.Remove(metaName)
		if err := os.Rename(partPath, metaName); err != nil {
			fmt.Fprintf(os.Stderr, "warn: rename %s -> %s: %v\n", partPath, metaName, err)
		}
		elapsed := time.Since(startT)
		rate := float64(metaSize) / elapsed.Seconds() / 1024 / 1024
		fmt.Printf("Done: %s in %s (%.1f MB/s, E2E decrypted)%s\n",
			formatBytes(metaSize), elapsed.Round(time.Millisecond), rate, verifyMsg)
		if dc, ok := controlDC.Load().(*webrtc.DataChannel); ok && dc != nil {
			ack, _ := json.Marshal(map[string]any{"type": "complete"})
			_ = dc.SendText(string(ack))
		}
		select {
		case transferDone <- nil:
		default:
		}
	}

	// On meta arrival, look for a matching .part to resume from. If the
	// first 4KB hash matches, populate recvBitmap and offset the file
	// pointer so already-have chunks aren't re-written.
	scanResume := func(prefixHash string) (alreadyHave int, bm []byte) {
		if prefixHash == "" {
			return 0, nil
		}
		partPath := metaName + ".part"
		st, err := os.Stat(partPath)
		if err != nil || st.Size() == 0 || st.Size() > metaSize {
			return 0, nil
		}
		f, err := os.Open(partPath)
		if err != nil {
			return 0, nil
		}
		defer f.Close()
		hashBuf := make([]byte, prefixHashSize)
		n, _ := io.ReadFull(f, hashBuf)
		got := sha256.Sum256(hashBuf[:n])
		if hex.EncodeToString(got[:]) != prefixHash {
			return 0, nil
		}
		// Prefix matches. Assume contiguous chunks 0..K-1 are valid where
		// K = floor(partSize / chunkSize). The trailing partial chunk (if
		// any) is discarded — it's safer to re-receive than to half-trust.
		fullChunks := int(st.Size() / metaChunkSize)
		if fullChunks > metaChunks {
			fullChunks = metaChunks
		}
		bm = newBitmap(metaChunks)
		for i := 0; i < fullChunks; i++ {
			setBit(bm, i)
		}
		return fullChunks, bm
	}

	onControlMessage := func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			return
		}
		var m struct {
			Type            string `json:"type"`
			Name            string `json:"name"`
			Size            int64  `json:"size"`
			Mime            string `json:"mime"`
			ChunkSize       int64  `json:"chunkSize"`
			TotalChunks     int    `json:"totalChunks"`
			ProtocolVersion int    `json:"protocolVersion"`
			Reason          string `json:"reason"`
			PrefixHash      string `json:"prefixHash"`
			FileHash        string `json:"fileHash"`
		}
		if err := json.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		switch m.Type {
		case "meta":
			stMu.Lock()
			defer stMu.Unlock()
			if gotMeta {
				return
			}
			metaName = m.Name
			metaSize = m.Size
			metaChunkSize = m.ChunkSize
			if metaChunkSize == 0 {
				metaChunkSize = chunkSize
			}
			metaChunks = m.TotalChunks
			if metaChunks == 0 {
				if metaChunkSize > 0 {
					metaChunks = int((metaSize + metaChunkSize - 1) / metaChunkSize)
				}
				if metaChunks == 0 {
					metaChunks = 1
				}
			}
			metaFileHash = m.PrefixHash
			_ = metaFileHash // silence unused (we stash prefix hash separately below)

			alreadyHave, resumeBm := scanResume(m.PrefixHash)
			partPath := metaName + ".part"
			var f *os.File
			var ferr error
			if alreadyHave > 0 {
				f, ferr = os.OpenFile(partPath, os.O_RDWR, 0644)
			} else {
				_ = os.Remove(partPath) // start fresh
				f, ferr = os.Create(partPath)
			}
			if ferr != nil {
				select {
				case transferDone <- ferr:
				default:
				}
				return
			}
			outFile = f
			recvBitmap = resumeBm
			if recvBitmap == nil {
				recvBitmap = newBitmap(metaChunks)
			}
			receivedCount = alreadyHave
			receivedBytes = int64(alreadyHave) * metaChunkSize
			if receivedBytes > metaSize {
				receivedBytes = metaSize
			}
			expectedHash = ""
			startT = time.Now()
			lastReport = startT
			gotMeta = true

			if alreadyHave > 0 {
				fmt.Printf("Resuming %q (%d/%d chunks already on disk)\n", metaName, alreadyHave, metaChunks)
			} else {
				fmt.Printf("Receiving %q (%s, %d chunks, v%d)\n", metaName, formatBytes(metaSize), metaChunks, m.ProtocolVersion)
			}

			// Send "resume" with our current bitmap so the sender can skip
			// already-have seqs in Phase 1. Always send (even when fresh,
			// empty bitmap) so the sender doesn't have to wait the full
			// resume-wait timeout.
			if dc, ok := controlDC.Load().(*webrtc.DataChannel); ok && dc != nil {
				resume, _ := json.Marshal(map[string]any{
					"type": "resume",
					"data": b64URL.EncodeToString(recvBitmap),
				})
				_ = dc.SendText(string(resume))
			}

			for _, p := range pending {
				storeChunk(p.seq, p.pt)
			}
			pending = nil
			finishIfComplete()
		case "done":
			stMu.Lock()
			if !finished {
				expectedHash = m.FileHash
			}
			finishIfComplete()
			stMu.Unlock()
		case "abort":
			select {
			case transferDone <- fmt.Errorf("sender aborted: %s", m.Reason):
			default:
			}
		}
	}

	onDataMessage := func(msg webrtc.DataChannelMessage) {
		if msg.IsString {
			onControlMessage(msg)
			return
		}
		if len(msg.Data) < seqHeaderBytes {
			return
		}
		seq := binary.BigEndian.Uint32(msg.Data[:seqHeaderBytes])
		ct := msg.Data[seqHeaderBytes:]
		pt, err := decryptChunk(aead, ct, seq)
		if err != nil {
			return
		}
		stMu.Lock()
		defer stMu.Unlock()
		if !gotMeta {
			pending = append(pending, pendingChunk{seq: seq, pt: pt})
			return
		}
		if !storeChunk(seq, pt) {
			return
		}
		now := time.Now()
		if now.Sub(lastReport) > 500*time.Millisecond {
			dt := now.Sub(lastReport).Seconds()
			rate := float64(receivedBytes-lastReceived) / dt / 1024 / 1024
			pct := float64(receivedBytes) / float64(metaSize) * 100
			if metaSize == 0 {
				pct = 100
			}
			fmt.Printf("\r  %s %5.1f%%  %s/%s  %.1f MB/s   ",
				progressBar(pct, 30), pct, formatBytes(receivedBytes), formatBytes(metaSize), rate)
			lastReport = now
			lastReceived = receivedBytes
		}
		finishIfComplete()
	}

	getOrCreatePc := func(idx int) (*webrtc.PeerConnection, error) {
		pcsMu.Lock()
		defer pcsMu.Unlock()
		if pcs[idx] != nil {
			return pcs[idx], nil
		}
		pc, err := pcAPI.NewPeerConnection(pcConfig)
		if err != nil {
			return nil, err
		}
		pcs[idx] = pc
		pc.OnICECandidate(func(c *webrtc.ICECandidate) {
			if c == nil {
				return
			}
			rid, _ := remotePeerID.Load().(string)
			if rid == "" {
				return
			}
			ci := c.ToJSON()
			_ = ws.write(sigMsg{Type: "ice", To: rid, Candidate: &ci, PcIdx: ptr(idx)})
		})
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			label := dc.Label()
			if label == "control" {
				controlDC.Store(dc)
				dc.OnMessage(onControlMessage)
			} else {
				dc.OnMessage(onDataMessage)
			}
		})
		return pc, nil
	}

	// Bitmap reporter — every 200ms send current bitmap on the control DC.
	go func() {
		ticker := time.NewTicker(bitmapInterval)
		defer ticker.Stop()
		var version int64
		for range ticker.C {
			stMu.Lock()
			if finished {
				stMu.Unlock()
				return
			}
			if recvBitmap == nil {
				stMu.Unlock()
				continue
			}
			version++
			payload, _ := json.Marshal(map[string]any{
				"type":     "bitmap",
				"version":  version,
				"received": receivedCount,
				"data":     b64URL.EncodeToString(recvBitmap),
			})
			stMu.Unlock()
			if dc, ok := controlDC.Load().(*webrtc.DataChannel); ok && dc != nil {
				_ = dc.SendText(string(payload))
			}
		}
	}()

	go func() {
		for {
			var msg sigMsg
			if err := wsConn.ReadJSON(&msg); err != nil {
				return
			}
			idx := 0
			if msg.PcIdx != nil {
				idx = *msg.PcIdx
			}
			if idx < 0 || idx >= numPCs {
				idx = 0
			}
			switch msg.Type {
			case "joined":
			case "offer":
				remotePeerID.Store(msg.From)
				pc, err := getOrCreatePc(idx)
				if err != nil {
					select {
					case transferDone <- err:
					default:
					}
					return
				}
				if msg.SDP == nil {
					continue
				}
				if err := pc.SetRemoteDescription(*msg.SDP); err != nil {
					select {
					case transferDone <- err:
					default:
					}
					return
				}
				ans, err := pc.CreateAnswer(nil)
				if err != nil {
					select {
					case transferDone <- err:
					default:
					}
					return
				}
				if err := pc.SetLocalDescription(ans); err != nil {
					select {
					case transferDone <- err:
					default:
					}
					return
				}
				rid, _ := remotePeerID.Load().(string)
				_ = ws.write(sigMsg{Type: "answer", To: rid, SDP: &ans, PcIdx: ptr(idx)})
			case "ice":
				pcsMu.Lock()
				pc := pcs[idx]
				pcsMu.Unlock()
				if pc != nil && msg.Candidate != nil {
					_ = pc.AddICECandidate(*msg.Candidate)
				}
			case "peer-left":
				stMu.Lock()
				done := finished
				stMu.Unlock()
				if done {
					return
				}
				go func() {
					deadline := time.Now().Add(30 * time.Second)
					for time.Now().Before(deadline) {
						time.Sleep(500 * time.Millisecond)
						stMu.Lock()
						isDone := finished
						stMu.Unlock()
						if isDone {
							return
						}
					}
					stMu.Lock()
					stillIncomplete := !finished
					stMu.Unlock()
					if stillIncomplete {
						select {
						case transferDone <- fmt.Errorf("sender disconnected before transfer completed"):
						default:
						}
					}
				}()
			case "error":
				select {
				case transferDone <- fmt.Errorf("signaling error: %s", msg.Reason):
				default:
				}
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	select {
	case err := <-transferDone:
		if err != nil {
			die(err)
		}
	case <-ctx.Done():
		die(fmt.Errorf("timeout"))
	}
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}

// ============================================================================
// Self-update + helpers
// ============================================================================

func checkForUpdate() {
	if os.Getenv("BEAMDROP_NO_UPDATE_CHECK") == "1" {
		return
	}

	cacheDir := filepath.Join(os.TempDir(), "beamdrop")
	cacheFile := filepath.Join(cacheDir, "latest-tag")

	var latest string
	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 6*time.Hour {
		if b, err := os.ReadFile(cacheFile); err == nil {
			latest = strings.TrimSpace(string(b))
		}
	}

	if latest == "" {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("https://api.github.com/repos/s-saga011/beamdrop-cli/releases/latest")
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var r struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
			return
		}
		latest = strings.TrimSpace(r.TagName)
		if latest != "" {
			_ = os.MkdirAll(cacheDir, 0755)
			_ = os.WriteFile(cacheFile, []byte(latest), 0644)
		}
	}

	if latest == "" || !versionLess(Version, latest) {
		return
	}

	fmt.Fprintf(os.Stderr, "[beamdrop] update available: %s → %s — run: beamdrop update\n", Version, latest)
	fmt.Fprintln(os.Stderr, "  (set BEAMDROP_NO_UPDATE_CHECK=1 to silence)")
	fmt.Fprintln(os.Stderr)
}

func runUpdate() {
	exePath, err := os.Executable()
	if err != nil {
		die(fmt.Errorf("locate self: %w", err))
	}
	if resolved, rerr := filepath.EvalSymlinks(exePath); rerr == nil {
		exePath = resolved
	}
	fmt.Printf("Current: %s (%s)\n", exePath, Version)

	fmt.Println("Checking GitHub for the latest release...")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/s-saga011/beamdrop-cli/releases/latest")
	if err != nil {
		die(fmt.Errorf("github api: %w", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		die(fmt.Errorf("github api status %d", resp.StatusCode))
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		die(fmt.Errorf("decode release: %w", err))
	}
	latest := rel.TagName
	if latest == "" {
		die(fmt.Errorf("github did not return a tag_name"))
	}

	if !versionLess(Version, latest) {
		fmt.Printf("Already at %s (latest is %s).\n", Version, latest)
		return
	}

	osName := runtime.GOOS
	arch := runtime.GOARCH
	ext := ""
	if osName == "windows" {
		ext = ".exe"
	}
	asset := fmt.Sprintf("beamdrop-%s-%s%s", osName, arch, ext)
	url := fmt.Sprintf("https://github.com/s-saga011/beamdrop-cli/releases/download/%s/%s", latest, asset)

	fmt.Printf("Downloading %s (%s)...\n", asset, latest)
	tmpFile := exePath + ".new"
	_ = os.Remove(tmpFile)

	var dlErr error
	for attempt := 1; attempt <= 5; attempt++ {
		if attempt > 1 {
			time.Sleep(2 * time.Second)
			fmt.Printf("  retry %d/5...\n", attempt)
		}
		dlErr = downloadTo(url, tmpFile)
		if dlErr == nil {
			break
		}
	}
	if dlErr != nil {
		_ = os.Remove(tmpFile)
		die(fmt.Errorf("download failed after 5 attempts: %w", dlErr))
	}

	if err := atomicReplaceBinary(exePath, tmpFile); err != nil {
		_ = os.Remove(tmpFile)
		die(fmt.Errorf("install: %w", err))
	}

	fmt.Printf("Updated %s → %s\n", Version, latest)
}

func downloadTo(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func atomicReplaceBinary(target, source string) error {
	if runtime.GOOS == "windows" {
		oldFile := target + ".old"
		_ = os.Remove(oldFile)
		if err := os.Rename(target, oldFile); err != nil {
			return fmt.Errorf("rename old: %w", err)
		}
		if err := os.Rename(source, target); err != nil {
			_ = os.Rename(oldFile, target)
			return fmt.Errorf("rename new: %w", err)
		}
		return nil
	}
	if err := os.Chmod(source, 0755); err != nil {
		return err
	}
	return os.Rename(source, target)
}

func cleanupStaleBinary() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if resolved, rerr := filepath.EvalSymlinks(exePath); rerr == nil {
		exePath = resolved
	}
	_ = os.Remove(exePath + ".old")
}

func versionLess(a, b string) bool {
	aa := strings.Split(strings.TrimPrefix(a, "v"), ".")
	bb := strings.Split(strings.TrimPrefix(b, "v"), ".")
	n := len(aa)
	if len(bb) < n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		ai, aerr := strconv.Atoi(aa[i])
		bi, berr := strconv.Atoi(bb[i])
		if aerr != nil || berr != nil {
			if aa[i] != bb[i] {
				return aa[i] < bb[i]
			}
			continue
		}
		if ai != bi {
			return ai < bi
		}
	}
	return len(aa) < len(bb)
}

const installSh = "https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.sh"
const installPs1 = "https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1"

func printShareInstructions(room, shareURL string) {
	fmt.Println()
	fmt.Println("┌─ Share with the recipient ──────────────────────────────────────")
	fmt.Println("│")
	fmt.Println("│  Full URL (works in any browser, includes E2E key):")
	fmt.Printf("│    %s\n", shareURL)
	fmt.Println("│")
	fmt.Println("│  macOS / Linux CLI (auto-installs if missing):")
	fmt.Printf("│    curl -fsSL %s | sh -s -- recv '%s'\n", installSh, shareURL)
	fmt.Println("│")
	fmt.Println("│  Windows PowerShell CLI (auto-installs if missing):")
	fmt.Printf("│    & ([scriptblock]::Create((irm %s))) recv '%s'\n", installPs1, shareURL)
	fmt.Println("│")
	fmt.Println("│  Already installed — update first, then receive:")
	fmt.Printf("│    beamdrop update && beamdrop recv '%s'\n", shareURL)
	fmt.Println("└──────────────────────────────────────────────────────────────────")
	fmt.Println()
	qrterminal.GenerateHalfBlock(shareURL, qrterminal.L, os.Stdout)
	fmt.Println()
	_ = room
}

func progressBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct/100*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), units[exp])
}
