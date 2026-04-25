// beamdrop CLI — minimal pion/webrtc-based file transfer.
//
// MVP intent: measure raw native WebRTC throughput on platforms where the
// browser SCTP stack is the bottleneck (notably Windows Chrome ~4.5 MB/s).
//
// Protocol (CLI-only, NOT compatible with browser v3 yet):
//   - Reuses beamdrop signaling: POST /api/rooms, WS /ws/{room}
//   - Single RTCPeerConnection, single ordered+reliable DataChannel
//   - Sender pushes binary chunks: [4-byte big-endian seq][payload]
//   - Sender sends final {"type":"done","totalBytes":N,"chunks":N} JSON
//   - No encryption (raw transfer for speed measurement)
//   - 256KB chunks (no Chrome 256KB DC limit on pion)
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mdp/qrterminal/v3"
	"github.com/pion/webrtc/v4"
)

// Version is set via -ldflags "-X main.Version=v0.1.2" at build time;
// the const fallback keeps `beamdrop --version` honest when run from `go run`.
var Version = "v0.1.5"

const (
	chunkSize     = 256 * 1024
	bufferedHigh  = 16 * 1024 * 1024
	bufferedLow   = 4 * 1024 * 1024
	defaultServer = "https://p2p.draft-publish.com"
)

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

// ============================================================================
// Main entry
// ============================================================================

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, `beamdrop CLI — high-speed P2P file transfer

Usage:
  beamdrop send <file> [--server URL]
  beamdrop recv <url>            # share URL printed by 'send'
  beamdrop recv <room> [--server URL]

Defaults:
  --server  https://p2p.draft-publish.com
`)
	os.Exit(1)
}

func die(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func parseFlags(args []string) (string, []string) {
	server := defaultServer
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--server":
			i++
			if i < len(args) {
				server = args[i]
			}
		default:
			positional = append(positional, a)
		}
	}
	return server, positional
}

// ============================================================================
// Sender
// ============================================================================

func runSend(args []string) {
	checkForUpdate()
	server, pos := parseFlags(args)
	if len(pos) < 1 {
		die(fmt.Errorf("usage: beamdrop send <file>"))
	}
	path := pos[0]

	file, err := os.Open(path)
	if err != nil {
		die(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		die(err)
	}
	totalBytes := stat.Size()

	fmt.Printf("File: %s (%s)\n", filepath.Base(path), formatBytes(totalBytes))

	room, err := createRoom(server)
	if err != nil {
		die(fmt.Errorf("createRoom: %w", err))
	}
	shareURL := fmt.Sprintf("%s/r/%s", server, room)
	printShareInstructions(room, shareURL)

	iceServers, err := fetchICE(server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: fetchICE failed: %v (using STUN only)\n", err)
		iceServers = []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	}

	ws, err := dialSignaling(server, room)
	if err != nil {
		die(fmt.Errorf("dial signaling: %w", err))
	}
	defer ws.Close()

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		die(err)
	}
	defer pc.Close()

	var remotePeerID string
	var dc *webrtc.DataChannel
	dcOpen := make(chan struct{})

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil || remotePeerID == "" {
			return
		}
		ci := c.ToJSON()
		_ = ws.WriteJSON(sigMsg{Type: "ice", To: remotePeerID, Candidate: &ci})
	})

	dc, err = pc.CreateDataChannel("file", &webrtc.DataChannelInit{
		Ordered: ptr(true),
	})
	if err != nil {
		die(err)
	}
	dc.SetBufferedAmountLowThreshold(bufferedLow)
	dc.OnOpen(func() {
		close(dcOpen)
	})

	// Listen for receiver control messages: 'ready' (with resume offset) and 'complete'.
	completeChan := make(chan struct{}, 1)
	readyChan := make(chan int64, 1)
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if !msg.IsString {
			return
		}
		var m struct {
			Type   string `json:"type"`
			Offset int64  `json:"offset"`
		}
		if err := json.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		switch m.Type {
		case "ready":
			select {
			case readyChan <- m.Offset:
			default:
			}
		case "complete":
			select {
			case completeChan <- struct{}{}:
			default:
			}
		}
	})

	myPeerID := ""
	wsRecvDone := make(chan error, 1)
	go func() {
		for {
			var msg sigMsg
			if err := ws.ReadJSON(&msg); err != nil {
				wsRecvDone <- err
				return
			}
			switch msg.Type {
			case "joined":
				myPeerID = msg.PeerID
			case "peer-joined":
				remotePeerID = msg.PeerID
				offer, err := pc.CreateOffer(nil)
				if err != nil {
					wsRecvDone <- err
					return
				}
				if err := pc.SetLocalDescription(offer); err != nil {
					wsRecvDone <- err
					return
				}
				_ = ws.WriteJSON(sigMsg{Type: "offer", To: remotePeerID, SDP: &offer})
			case "answer":
				if msg.SDP != nil {
					_ = pc.SetRemoteDescription(*msg.SDP)
				}
			case "ice":
				if msg.Candidate != nil {
					_ = pc.AddICECandidate(*msg.Candidate)
				}
			case "peer-left":
				wsRecvDone <- fmt.Errorf("receiver disconnected")
				return
			case "error":
				wsRecvDone <- fmt.Errorf("signaling error: %s", msg.Reason)
				return
			}
		}
	}()
	_ = myPeerID

	fmt.Println("Waiting for receiver...")
	select {
	case <-dcOpen:
		fmt.Println("Connected, starting transfer.")
	case err := <-wsRecvDone:
		die(err)
	case <-time.After(10 * time.Minute):
		die(fmt.Errorf("timeout waiting for receiver"))
	}

	// Compute prefix hash so the receiver can verify any existing .part file
	// belongs to the same source (resume safety check).
	prefixSize := int64(4096)
	if totalBytes < prefixSize {
		prefixSize = totalBytes
	}
	prefix := make([]byte, prefixSize)
	if _, err := file.ReadAt(prefix, 0); err != nil && err != io.EOF {
		die(fmt.Errorf("read prefix: %w", err))
	}
	prefixSum := sha256.Sum256(prefix)
	prefixHash := hex.EncodeToString(prefixSum[:])

	// Send meta
	metaJSON, _ := json.Marshal(map[string]any{
		"type":        "meta",
		"name":        filepath.Base(path),
		"size":        totalBytes,
		"chunkSize":   chunkSize,
		"totalChunks": (totalBytes + chunkSize - 1) / chunkSize,
		"prefixHash":  prefixHash,
	})
	if err := dc.SendText(string(metaJSON)); err != nil {
		die(err)
	}

	// Wait for receiver "ready" with resume offset (0 = fresh start).
	var startOffset int64
	select {
	case startOffset = <-readyChan:
	case <-time.After(30 * time.Second):
		die(fmt.Errorf("receiver did not send 'ready' within 30s"))
	}

	if startOffset >= totalBytes {
		fmt.Println("Receiver already has the complete file. Sending DONE only.")
	} else if startOffset > 0 {
		fmt.Printf("Resuming from offset %s (skipping %s already received)\n",
			formatBytes(startOffset), formatBytes(startOffset))
		if _, err := file.Seek(startOffset, 0); err != nil {
			die(fmt.Errorf("seek to resume offset: %w", err))
		}
	}

	// Full-file SHA-256 for end-to-end integrity. For resume cases we have
	// to pre-hash the bytes we're about to skip so the final digest covers
	// the entire file.
	hasher := sha256.New()
	if startOffset > 0 {
		fmt.Printf("Pre-hashing %s already-sent prefix...\n", formatBytes(startOffset))
		ph, err := os.Open(path)
		if err != nil {
			die(fmt.Errorf("open for prefix hash: %w", err))
		}
		if _, err := io.CopyN(hasher, ph, startOffset); err != nil {
			ph.Close()
			die(fmt.Errorf("hash prefix: %w", err))
		}
		ph.Close()
	}

	// Stream file with simple back-pressure on bufferedAmount
	bufferLow := make(chan struct{}, 1)
	dc.OnBufferedAmountLow(func() {
		select {
		case bufferLow <- struct{}{}:
		default:
		}
	})

	buf := make([]byte, chunkSize)
	seqBytes := make([]byte, 4)
	startT := time.Now()
	sent := startOffset
	seq := uint32(startOffset / chunkSize)
	lastReport := startT
	lastSentBytes := startOffset
	if startOffset < totalBytes {
		for {
			n, rerr := io.ReadFull(file, buf)
			if n == 0 && rerr == io.EOF {
				break
			}
			if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
				die(rerr)
			}
			hasher.Write(buf[:n])
			// Build [4-byte seq][payload]
			out := make([]byte, 4+n)
			binary.BigEndian.PutUint32(seqBytes, seq)
			copy(out[:4], seqBytes)
			copy(out[4:], buf[:n])

			// Wait for buffer if too full
			for dc.BufferedAmount() > bufferedHigh {
				<-bufferLow
			}
			if err := dc.Send(out); err != nil {
				die(fmt.Errorf("send seq=%d: %w", seq, err))
			}
			sent += int64(n)
			seq++

			now := time.Now()
			if now.Sub(lastReport) > 500*time.Millisecond {
				dt := now.Sub(lastReport).Seconds()
				rate := float64(sent-lastSentBytes) / dt / 1024 / 1024
				pct := float64(sent) / float64(totalBytes) * 100
				fmt.Printf("\r  %5.1f%%  %s/%s  %.1f MB/s   ", pct, formatBytes(sent), formatBytes(totalBytes), rate)
				lastReport = now
				lastSentBytes = sent
			}
			if rerr == io.ErrUnexpectedEOF || rerr == io.EOF {
				break
			}
		}
	}

	// done message — include full SHA-256 for end-to-end verification
	fileHash := hex.EncodeToString(hasher.Sum(nil))
	doneJSON, _ := json.Marshal(map[string]any{
		"type":       "done",
		"totalBytes": sent,
		"chunks":     seq,
		"fileHash":   fileHash,
	})
	_ = dc.SendText(string(doneJSON))

	// Wait for buffer to fully drain so the wire delivery completes.
	for dc.BufferedAmount() > 0 {
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for the receiver to ACK with {"type":"complete"} so we don't tear
	// down the WS (which would race a "peer-left" against the final DC chunk).
	select {
	case <-completeChan:
	case <-time.After(30 * time.Second):
		fmt.Fprintln(os.Stderr, "warning: receiver did not confirm completion within 30s")
	}

	elapsed := time.Since(startT)
	rate := float64(sent) / elapsed.Seconds() / 1024 / 1024
	fmt.Printf("\rDone: %s in %s (%.1f MB/s)                       \n",
		formatBytes(sent), elapsed.Round(time.Millisecond), rate)
}

// ============================================================================
// Receiver
// ============================================================================

func runRecv(args []string) {
	checkForUpdate()
	server, pos := parseFlags(args)
	if len(pos) < 1 {
		die(fmt.Errorf("usage: beamdrop recv <url-or-room>"))
	}
	target := pos[0]
	room := target
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// Parse URL like https://server/r/ROOM
		u, err := url.Parse(target)
		if err != nil {
			die(fmt.Errorf("parse url: %w", err))
		}
		server = u.Scheme + "://" + u.Host
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) < 2 || parts[0] != "r" {
			die(fmt.Errorf("URL must be of form server/r/ROOM"))
		}
		room = parts[1]
	}

	iceServers, err := fetchICE(server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: fetchICE failed: %v\n", err)
		iceServers = []webrtc.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	}

	ws, err := dialSignaling(server, room)
	if err != nil {
		die(fmt.Errorf("dial signaling: %w", err))
	}
	defer ws.Close()

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{ICEServers: iceServers})
	if err != nil {
		die(err)
	}
	defer pc.Close()

	var remotePeerID string
	var (
		mu          sync.Mutex
		meta        struct {
			Name      string `json:"name"`
			Size      int64  `json:"size"`
			ChunkSize int    `json:"chunkSize"`
		}
		outFile  *os.File
		startT   time.Time
		received int64
		gotMeta  bool
	)

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil || remotePeerID == "" {
			return
		}
		ci := c.ToJSON()
		_ = ws.WriteJSON(sigMsg{Type: "ice", To: remotePeerID, Candidate: &ci})
	})

	transferDone := make(chan error, 1)

	var (
		recvDC     *webrtc.DataChannel
		transferOK bool // set true after "done" handler completes successfully
		hasher     hash.Hash
	)

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		fmt.Printf("DataChannel %q opened\n", dc.Label())
		recvDC = dc
		var lastReport time.Time
		var lastReceivedBytes int64
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if msg.IsString {
				var hdr struct {
					Type       string `json:"type"`
					Name       string `json:"name"`
					Size       int64  `json:"size"`
					ChunkSize  int    `json:"chunkSize"`
					PrefixHash string `json:"prefixHash"`
				}
				_ = json.Unmarshal(msg.Data, &hdr)
				switch hdr.Type {
				case "meta":
					mu.Lock()
					meta.Name = hdr.Name
					meta.Size = hdr.Size
					meta.ChunkSize = hdr.ChunkSize
					gotMeta = true
					hasher = sha256.New()
					partPath := meta.Name + ".part"
					var resumeOffset int64

					// Look for an existing partial file with matching prefix hash.
					if st, err := os.Stat(partPath); err == nil && st.Size() <= meta.Size {
						f, ferr := os.Open(partPath)
						if ferr == nil {
							prefixSize := int64(4096)
							if st.Size() < prefixSize {
								prefixSize = st.Size()
							}
							pbuf := make([]byte, prefixSize)
							n, _ := io.ReadFull(f, pbuf)
							_ = f.Close()
							if hdr.PrefixHash != "" {
								sum := sha256.Sum256(pbuf[:n])
								if hex.EncodeToString(sum[:]) == hdr.PrefixHash {
									resumeOffset = st.Size()
									fmt.Printf("Found %q (%s/%s already received) — resuming\n",
										partPath, formatBytes(resumeOffset), formatBytes(meta.Size))
									// Hash the existing prefix so the final digest covers the whole file.
									ph, herr := os.Open(partPath)
									if herr == nil {
										fmt.Printf("Hashing existing %s...\n", formatBytes(resumeOffset))
										if _, herr := io.CopyN(hasher, ph, resumeOffset); herr != nil {
											fmt.Fprintf(os.Stderr, "warn: prefix hash failed: %v (full checksum will be off)\n", herr)
										}
										ph.Close()
									}
								} else {
									fmt.Printf("Found %q but prefix differs — discarding and starting fresh\n", partPath)
									_ = os.Remove(partPath)
								}
							}
						}
					}

					var f *os.File
					var ferr error
					if resumeOffset > 0 {
						f, ferr = os.OpenFile(partPath, os.O_WRONLY, 0644)
						if ferr == nil {
							_, ferr = f.Seek(resumeOffset, 0)
						}
					} else {
						f, ferr = os.Create(partPath)
					}
					if ferr != nil {
						transferDone <- ferr
						mu.Unlock()
						return
					}
					outFile = f
					received = resumeOffset
					startT = time.Now()
					lastReport = startT
					lastReceivedBytes = resumeOffset
					mu.Unlock()
					if resumeOffset == 0 {
						fmt.Printf("Receiving %q (%s)\n", meta.Name, formatBytes(meta.Size))
					}

					// Tell sender where to resume from
					ready, _ := json.Marshal(map[string]any{"type": "ready", "offset": resumeOffset})
					_ = dc.SendText(string(ready))
				case "done":
					var doneHdr struct {
						FileHash string `json:"fileHash"`
					}
					_ = json.Unmarshal(msg.Data, &doneHdr)

					mu.Lock()
					if outFile != nil {
						_ = outFile.Sync()
						_ = outFile.Close()
						outFile = nil
					}

					partPath := meta.Name + ".part"
					var got string
					if hasher != nil {
						got = hex.EncodeToString(hasher.Sum(nil))
					}
					if doneHdr.FileHash != "" && got != "" && got != doneHdr.FileHash {
						fmt.Fprintf(os.Stderr, "\nERROR: SHA-256 mismatch (expected %s, got %s). %q kept for inspection.\n",
							doneHdr.FileHash[:12]+"...", got[:12]+"...", partPath)
						mu.Unlock()
						transferDone <- fmt.Errorf("checksum mismatch — partial file left at %s", partPath)
						return
					}
					// Promote .part → final filename
					if _, err := os.Stat(partPath); err == nil {
						_ = os.Remove(meta.Name) // overwrite if exists
						if err := os.Rename(partPath, meta.Name); err != nil {
							fmt.Fprintf(os.Stderr, "warn: rename %s -> %s: %v\n", partPath, meta.Name, err)
						}
					}
					elapsed := time.Since(startT)
					rate := float64(received) / elapsed.Seconds() / 1024 / 1024
					verifyMsg := ""
					if doneHdr.FileHash != "" && got == doneHdr.FileHash {
						verifyMsg = " (SHA-256 verified)"
					}
					fmt.Printf("\rDone: %s in %s (%.1f MB/s)%s                     \n",
						formatBytes(received), elapsed.Round(time.Millisecond), rate, verifyMsg)
					transferOK = true
					mu.Unlock()
					// ACK so the sender can safely tear down the WebSocket.
					ack, _ := json.Marshal(map[string]any{"type": "complete"})
					_ = dc.SendText(string(ack))
					transferDone <- nil
				}
				return
			}
			// Binary chunk: [4-byte seq][payload]
			if len(msg.Data) < 4 {
				return
			}
			payload := msg.Data[4:]
			mu.Lock()
			if outFile != nil {
				if _, err := outFile.Write(payload); err != nil {
					transferDone <- err
					mu.Unlock()
					return
				}
				if hasher != nil {
					hasher.Write(payload)
				}
				received += int64(len(payload))
			}
			now := time.Now()
			if now.Sub(lastReport) > 500*time.Millisecond && gotMeta {
				dt := now.Sub(lastReport).Seconds()
				rate := float64(received-lastReceivedBytes) / dt / 1024 / 1024
				pct := float64(received) / float64(meta.Size) * 100
				fmt.Printf("\r  %5.1f%%  %s/%s  %.1f MB/s   ", pct, formatBytes(received), formatBytes(meta.Size), rate)
				lastReport = now
				lastReceivedBytes = received
			}
			mu.Unlock()
		})
		dc.OnClose(func() {
			// If the DC closed before "done" arrived, that is the real
			// disconnect signal; report it so the main loop unblocks.
			mu.Lock()
			if !transferOK {
				select {
				case transferDone <- fmt.Errorf("data channel closed mid-transfer"):
				default:
				}
			}
			mu.Unlock()
		})
	})
	_ = recvDC

	myPeerID := ""
	go func() {
		for {
			var msg sigMsg
			if err := ws.ReadJSON(&msg); err != nil {
				return
			}
			switch msg.Type {
			case "joined":
				myPeerID = msg.PeerID
			case "offer":
				remotePeerID = msg.From
				if msg.SDP != nil {
					if err := pc.SetRemoteDescription(*msg.SDP); err != nil {
						transferDone <- err
						return
					}
					ans, err := pc.CreateAnswer(nil)
					if err != nil {
						transferDone <- err
						return
					}
					if err := pc.SetLocalDescription(ans); err != nil {
						transferDone <- err
						return
					}
					_ = ws.WriteJSON(sigMsg{Type: "answer", To: remotePeerID, SDP: &ans})
				}
			case "ice":
				if msg.Candidate != nil {
					_ = pc.AddICECandidate(*msg.Candidate)
				}
			case "peer-left":
				// The signaling channel can drop before the final DC chunks
				// land; rely on dc.OnClose / explicit "done" instead of
				// killing the transfer here.
				mu.Lock()
				if !transferOK && received < meta.Size {
					// We may still receive remaining buffered DC data —
					// give the data channel up to 30s to deliver before
					// declaring failure.
					go func() {
						deadline := time.Now().Add(30 * time.Second)
						for time.Now().Before(deadline) {
							time.Sleep(500 * time.Millisecond)
							mu.Lock()
							ok := transferOK
							mu.Unlock()
							if ok {
								return
							}
						}
						mu.Lock()
						stillIncomplete := !transferOK
						mu.Unlock()
						if stillIncomplete {
							select {
							case transferDone <- fmt.Errorf("sender disconnected before transfer completed"):
							default:
							}
						}
					}()
				}
				mu.Unlock()
			case "error":
				transferDone <- fmt.Errorf("signaling error: %s", msg.Reason)
				return
			}
		}
	}()
	_ = myPeerID

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

// ============================================================================
// Helpers
// ============================================================================

func ptr[T any](v T) *T { return &v }

// checkForUpdate hits GitHub's /releases/latest, compares the tag with
// our embedded Version, and prints a one-line nudge if a newer version
// exists. Caches the latest tag in a small temp file for 6h to avoid
// hammering the API on repeated invocations.
func checkForUpdate() {
	if os.Getenv("BEAMDROP_NO_UPDATE_CHECK") == "1" {
		return
	}

	cacheDir := filepath.Join(os.TempDir(), "beamdrop")
	cacheFile := filepath.Join(cacheDir, "latest-tag")

	var latest string
	// Try cache first
	if info, err := os.Stat(cacheFile); err == nil && time.Since(info.ModTime()) < 6*time.Hour {
		if b, err := os.ReadFile(cacheFile); err == nil {
			latest = strings.TrimSpace(string(b))
		}
	}

	// Fall back to GitHub API
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

	fmt.Fprintf(os.Stderr, "[beamdrop] update available: %s → %s\n", Version, latest)
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "  irm https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.ps1 | iex")
	} else {
		fmt.Fprintln(os.Stderr, "  curl -fsSL https://raw.githubusercontent.com/s-saga011/beamdrop-cli/main/install.sh | sh")
	}
	fmt.Fprintln(os.Stderr, "  (set BEAMDROP_NO_UPDATE_CHECK=1 to silence)")
	fmt.Fprintln(os.Stderr)
}

// versionLess reports whether a < b for vMAJOR.MINOR.PATCH-style strings.
// Unparsable components fall through to string comparison.
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

// printShareInstructions emits a copy-pasteable, install-or-reuse one-liner
// for each platform, plus an ASCII QR for phone scanning.
func printShareInstructions(room, shareURL string) {
	fmt.Println()
	fmt.Println("┌─ Share with the recipient ──────────────────────────────────────")
	fmt.Println("│")
	fmt.Println("│  macOS / Linux (auto-installs CLI if missing):")
	fmt.Printf("│    curl -fsSL %s | sh -s -- recv %s\n", installSh, room)
	fmt.Println("│")
	fmt.Println("│  Windows PowerShell (auto-installs CLI if missing):")
	fmt.Printf("│    & ([scriptblock]::Create((irm %s))) recv %s\n", installPs1, room)
	fmt.Println("│")
	fmt.Println("│  Already installed:")
	fmt.Printf("│    beamdrop recv %s\n", room)
	fmt.Println("│")
	fmt.Printf("│  Share URL: %s\n", shareURL)
	fmt.Println("└──────────────────────────────────────────────────────────────────")
	fmt.Println()
	// QR code for scanning the share URL
	qrterminal.GenerateHalfBlock(shareURL, qrterminal.L, os.Stdout)
	fmt.Println()
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
