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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

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
	fmt.Printf("Share: %s/r/%s   (or: beamdrop recv %s)\n", server, room, room)

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

	// Send meta
	metaJSON, _ := json.Marshal(map[string]any{
		"type":       "meta",
		"name":       filepath.Base(path),
		"size":       totalBytes,
		"chunkSize":  chunkSize,
		"totalChunks": (totalBytes + chunkSize - 1) / chunkSize,
	})
	if err := dc.SendText(string(metaJSON)); err != nil {
		die(err)
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
	var sent int64
	var seq uint32
	lastReport := startT
	lastSentBytes := int64(0)
	for {
		n, rerr := io.ReadFull(file, buf)
		if n == 0 && rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF && rerr != io.EOF {
			die(rerr)
		}
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

	// done message
	doneJSON, _ := json.Marshal(map[string]any{"type": "done", "totalBytes": sent, "chunks": seq})
	_ = dc.SendText(string(doneJSON))

	// Wait for buffer to fully drain so we don't close mid-flight
	for dc.BufferedAmount() > 0 {
		time.Sleep(50 * time.Millisecond)
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

	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		fmt.Printf("DataChannel %q opened\n", dc.Label())
		var lastReport time.Time
		var lastReceivedBytes int64
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if msg.IsString {
				var hdr struct {
					Type      string `json:"type"`
					Name      string `json:"name"`
					Size      int64  `json:"size"`
					ChunkSize int    `json:"chunkSize"`
				}
				_ = json.Unmarshal(msg.Data, &hdr)
				switch hdr.Type {
				case "meta":
					mu.Lock()
					meta.Name = hdr.Name
					meta.Size = hdr.Size
					meta.ChunkSize = hdr.ChunkSize
					gotMeta = true
					f, err := os.Create(meta.Name)
					if err != nil {
						transferDone <- err
						mu.Unlock()
						return
					}
					outFile = f
					startT = time.Now()
					lastReport = startT
					mu.Unlock()
					fmt.Printf("Receiving %q (%s)\n", meta.Name, formatBytes(meta.Size))
				case "done":
					mu.Lock()
					if outFile != nil {
						_ = outFile.Sync()
						_ = outFile.Close()
					}
					elapsed := time.Since(startT)
					rate := float64(received) / elapsed.Seconds() / 1024 / 1024
					fmt.Printf("\rDone: %s in %s (%.1f MB/s)                     \n",
						formatBytes(received), elapsed.Round(time.Millisecond), rate)
					mu.Unlock()
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
	})

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
				transferDone <- fmt.Errorf("sender disconnected")
				return
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
