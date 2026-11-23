package main

// WebTransport data path (CLI sender -> browser receiver on the local network).
//
// Chromium's WebRTC network thread caps DataChannel receive at a few MB/s on
// some machines no matter what the sender does; WebTransport is handled in
// the browser's network process and does not have that ceiling. WebRTC still
// connects first and keeps carrying the control messages (meta, resume,
// bitmap, complete) and the retransmit channel; only the bulk chunks move.
//
// The browser cannot listen, so we are the QUIC/HTTP3 server: an ephemeral
// UDP port, a throwaway self-signed certificate the browser pins by hash
// (serverCertificateHashes: ECDSA, valid <= 14 days), and a per-transfer
// token so nobody else on the LAN can pull the stream.
//
// Wire format on each unidirectional stream (opened by us), repeated:
//   [4-byte BE seq][4-byte BE ciphertext length][ciphertext]
// with the same seq numbering and ciphertext as the DataChannel frames.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

const (
	wtStreams      = 4               // unidirectional streams, one worker each
	wtMaxConns     = 1               // QUIC connections offered (BEAMDROP_WT_CONNS overrides, 1-8); 2-6 measured no faster
	wtReadyTimeout = 5 * time.Second // receiver must answer the offer within this
	wtWriteBuf     = 256 * 1024      // per-stream write coalescing
)

// wtReply is the receiver's answer to our offer (control DC).
type wtReply struct {
	ok     bool
	idx    int  // which offered URL it connected to
	conns  int  // sessions it opened to that URL (0 = an older page: one)
	later  bool // with !ok: it keeps trying (a permission prompt is open)
	reason string
}

type wtServer struct {
	srv      *webtransport.Server
	conn     *net.UDPConn
	token    string
	urls     []string
	certHash string
	conns    int

	mu       sync.Mutex
	sessions map[int]*webtransport.Session
	arrived  chan struct{}
}

// wtLocalAddrs returns our own address on each distinct selected ICE pair:
// the addresses the receiver is demonstrably reaching us on.
func wtLocalAddrs(pcs []*webrtc.PeerConnection) []netip.Addr {
	var out []netip.Addr
	for _, pc := range pcs {
		if pc == nil || pc.SCTP() == nil || pc.SCTP().Transport() == nil || pc.SCTP().Transport().ICETransport() == nil {
			continue
		}
		pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		if err != nil || pair == nil || pair.Local == nil || pair.Local.Typ != webrtc.ICECandidateTypeHost {
			continue
		}
		a, err := netip.ParseAddr(pair.Local.Address)
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if a.Is6() && a.IsLinkLocalUnicast() {
			continue // needs a zone id, which a URL cannot carry
		}
		seen := false
		for _, b := range out {
			seen = seen || a == b
		}
		if !seen {
			out = append(out, a)
		}
	}
	return out
}

func startWT(addrs []netip.Addr) (*wtServer, error) {
	if len(addrs) == 0 {
		return nil, errors.New("no usable local address")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "beamdrop"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, a := range addrs {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(a.AsSlice()))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	tok := make([]byte, 16)
	if _, err := rand.Read(tok); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	advPort := port
	if os.Getenv("BEAMDROP_WT_TEST_BADPORT") == "1" {
		advPort = port%60000 + 1024 + 1 // test hook: an offer nobody can reach
	}

	w := &wtServer{
		conn:     conn,
		token:    hex.EncodeToString(tok),
		certHash: base64.StdEncoding.EncodeToString(sum[:]),
		sessions: map[int]*webtransport.Session{},
		arrived:  make(chan struct{}, 8),
		conns:    wtMaxConns,
	}
	if n, err := strconv.Atoi(os.Getenv("BEAMDROP_WT_CONNS")); err == nil && n >= 1 && n <= 8 {
		w.conns = n
	}
	if t, err := netip.ParseAddr(os.Getenv("BEAMDROP_WT_TEST_ADDR")); err == nil {
		addrs = []netip.Addr{t} // test hook: offer exactly this address (e.g. IPv4 only)
	}
	if os.Getenv("BEAMDROP_WT_TEST_BADPORT") == "2" {
		addrs = []netip.Addr{netip.MustParseAddr("192.0.2.1")} // test hook: packets vanish (TEST-NET-1)
	}
	for _, a := range addrs {
		w.urls = append(w.urls, "https://"+netip.AddrPortFrom(a, uint16(advPort)).String()+"/wt")
	}

	// quic-go warns on stderr when the OS caps the UDP receive buffer
	// (stock Linux); we mostly send, and the warning would land mid-progress.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	if !debugLog {
		log.SetOutput(io.Discard) // webtransport-go logs connection teardown via the std logger
	}
	mux := http.NewServeMux()
	w.srv = &webtransport.Server{
		H3: &http3.Server{
			TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			}),
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  15 * time.Second,
				KeepAlivePeriod: 5 * time.Second,
			},
			Handler: mux,
		},
		// Any page origin may connect: the token is the access control.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	mux.HandleFunc("/wt", func(rw http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if subtle.ConstantTimeCompare([]byte(q.Get("t")), []byte(w.token)) != 1 {
			dbgf("[wt] rejected session from %s: bad token\n", r.RemoteAddr)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
		idx, _ := strconv.Atoi(q.Get("i"))
		if c, _ := strconv.Atoi(q.Get("c")); c > 0 && c < 16 {
			idx += c << 8 // extra connection c to URL i (see wtServer.session)
		}
		sess, err := w.srv.Upgrade(rw, r)
		if err != nil {
			dbgf("[wt] upgrade failed: %v\n", err)
			return
		}
		dbgf("[wt] session %d from %s\n", idx, sess.RemoteAddr())
		w.mu.Lock()
		old := w.sessions[idx]
		w.sessions[idx] = sess
		w.mu.Unlock()
		if old != nil {
			_ = old.CloseWithError(0, "replaced")
		}
		select {
		case w.arrived <- struct{}{}:
		default:
		}
		<-sess.Context().Done()
	})
	go func() {
		if err := w.srv.Serve(conn); err != nil {
			dbgf("[wt] listener stopped: %v\n", err)
		}
	}()
	dbgf("[wt] listening on udp :%d, offering %v certHash=%s token=%s\n", port, w.urls, w.certHash, w.token)
	return w, nil
}

func (w *wtServer) offerJSON() string {
	b, _ := json.Marshal(map[string]any{
		"type":     "wt-offer",
		"urls":     w.urls,
		"certHash": w.certHash,
		"token":    w.token,
		// One QUIC connection sends from one goroutine, a packet per
		// syscall: the sender was the limit at ~45-55 MB/s. The page may
		// open this many sessions (each its own connection) to one URL.
		"conns": w.conns,
	})
	return string(b)
}

// session returns the session the receiver said it connected with. The
// receiver's "ready" can overtake our own Upgrade bookkeeping by a moment.
func (w *wtServer) session(idx, conn int) *webtransport.Session {
	idx += conn << 8
	deadline := time.After(time.Second)
	for {
		w.mu.Lock()
		s := w.sessions[idx]
		w.mu.Unlock()
		if s != nil {
			return s
		}
		select {
		case <-w.arrived:
		case <-deadline:
			return nil
		}
	}
}

func (w *wtServer) close() {
	if w == nil {
		return
	}
	// Server.Close waits for its sessions; close them first, and never let
	// teardown hold up the transfer.
	w.mu.Lock()
	for _, s := range w.sessions {
		go s.CloseWithError(0, "")
	}
	w.mu.Unlock()
	go func() {
		_ = w.srv.Close()
		_ = w.conn.Close()
	}()
}

// wtSender is an established session with its streams open.
type wtSender struct {
	srv     *wtServer
	sess    []*webtransport.Session
	streams []*webtransport.SendStream
	broken  atomic.Bool
}

// sender turns the receiver's "ready" into a wtSender with its streams open.
// nil (reason in the debug log) means the sessions are not usable.
func (srv *wtServer) sender(r wtReply) *wtSender {
	s := &wtSender{srv: srv}
	for c := 0; c < max(r.conns, 1) && c < srv.conns; c++ {
		if sess := srv.session(r.idx, c); sess != nil {
			s.sess = append(s.sess, sess)
		}
	}
	if len(s.sess) == 0 {
		dbgf("[wt] receiver reported ready but no session %d\n", r.idx)
		return nil
	}
	// Same number of workers either way: with several connections, two
	// streams on each.
	per := wtStreams
	if len(s.sess) > 1 {
		per = 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, sess := range s.sess {
		for i := 0; i < per; i++ {
			str, err := sess.OpenUniStreamSync(ctx)
			if err != nil {
				dbgf("[wt] open stream: %v\n", err)
				return nil
			}
			s.streams = append(s.streams, str)
		}
	}
	dbgf("[wt] %d connection(s), %d streams\n", len(s.sess), len(s.streams))
	return s
}

// negotiateWT offers the WebTransport path to the receiver and waits for its
// answer. A nil sender means "carry on with the data channels" (reason in
// the debug log). In that case a non-nil server is still listening: the
// receiver is waiting on a browser permission prompt and may yet send
// "wt-ready" (see wtServer.sender); the caller closes it.
func negotiateWT(pcs []*webrtc.PeerConnection, controlDC *webrtc.DataChannel, replies <-chan wtReply, done func() bool) (*wtSender, *wtServer) {
	srv, err := startWT(wtLocalAddrs(pcs))
	if err != nil {
		dbgf("[wt] not offered: %v\n", err)
		return nil, nil
	}
	if err := controlDC.SendText(srv.offerJSON()); err != nil {
		dbgf("[wt] offer not sent: %v\n", err)
		srv.close()
		return nil, nil
	}
	start := time.Now()
	timeout := time.After(wtReadyTimeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case r := <-replies:
			if !r.ok {
				dbgf("[wt] receiver declined after %s (%s, later=%v) - using data channels\n", time.Since(start).Round(time.Millisecond), r.reason, r.later)
				if r.later {
					return nil, srv
				}
				srv.close()
				return nil, nil
			}
			if s := srv.sender(r); s != nil {
				return s, srv
			}
			srv.close()
			return nil, nil
		case <-timeout:
			dbgf("[wt] no answer in %s - using data channels\n", wtReadyTimeout)
			srv.close()
			return nil, nil
		case <-tick.C:
			if done() {
				srv.close()
				return nil, nil
			}
		}
	}
}

// send runs one worker per stream until next() is exhausted or the session
// breaks (then it returns the error; chunks already pulled but not delivered
// are picked up by the bitmap-driven retransmit phase).
func (s *wtSender) send(next func() (uint32, []byte, bool), encrypt func(uint32, []byte) []byte, sent func(int), done func() bool) error {
	var killAfter int64
	if mb, _ := strconv.Atoi(os.Getenv("BEAMDROP_WT_TEST_KILL_MB")); mb > 0 {
		killAfter = int64(mb) << 20 // test hook: drop the session mid-transfer
	}
	var total atomic.Int64
	var errMu sync.Mutex
	var firstErr error
	fail := func(err error) {
		s.broken.Store(true)
		errMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		errMu.Unlock()
	}
	var wg sync.WaitGroup
	for _, str := range s.streams {
		wg.Add(1)
		go func(str *webtransport.SendStream) {
			defer wg.Done()
			bw := bufio.NewWriterSize(str, wtWriteBuf)
			var hdr [8]byte
			for !s.broken.Load() && !done() {
				seq, pt, ok := next()
				if !ok {
					if err := bw.Flush(); err != nil {
						fail(err)
						return
					}
					_ = str.Close() // FIN; the session stays up until we exit
					return
				}
				ct := encrypt(seq, pt)
				binary.BigEndian.PutUint32(hdr[:4], seq)
				binary.BigEndian.PutUint32(hdr[4:], uint32(len(ct)))
				_, err := bw.Write(hdr[:])
				if err == nil {
					_, err = bw.Write(ct)
				}
				if err != nil {
					fail(err)
					return
				}
				sent(len(pt))
				if killAfter > 0 && total.Add(int64(len(pt))) >= killAfter && !s.broken.Swap(true) {
					fmt.Fprintf(os.Stderr, "\n[test] closing the WebTransport session after %d MB\n", killAfter>>20)
					fail(errors.New("test kill"))
					for _, sess := range s.sess {
						go sess.CloseWithError(0, "test")
					}
					return
				}
			}
			// Stopped early (transfer complete or another stream failed).
			_ = bw.Flush()
		}(str)
	}
	wg.Wait()
	errMu.Lock()
	defer errMu.Unlock()
	return firstErr
}

// alive reports whether the session is still usable.
func (s *wtSender) alive() bool {
	if s == nil || s.broken.Load() {
		return false
	}
	for _, sess := range s.sess {
		if sess.Context().Err() != nil {
			return false
		}
	}
	return true
}
