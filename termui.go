package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/pion/webrtc/v4"
)

// asciiUI is true when the output can't be trusted to draw box-drawing and
// block characters: a legacy Windows console (non-UTF-8 code page), or
// Windows output that is piped/redirected, where PowerShell decodes our
// UTF-8 with the console code page and shows mojibake. Then the share box,
// progress bar and QR code fall back to plain ASCII.
// BEAMDROP_ASCII=1 / =0 forces it either way.
var asciiUI = func() bool {
	switch os.Getenv("BEAMDROP_ASCII") {
	case "1":
		return true
	case "0":
		return false
	}
	return platformNeedsASCII()
}()

// debugLog gates connection-level chatter (signaling messages, ICE
// candidates and state changes): hundreds of lines per transfer that bury
// the progress bar. BEAMDROP_DEBUG=1 brings them back.
var debugLog = os.Getenv("BEAMDROP_DEBUG") == "1"

func dbgf(format string, a ...any) {
	if debugLog {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

// describeRoute reports the ICE candidate pair each connection actually
// selected. Without it "is this going direct or through the TURN relay / a
// VPN tunnel?" could only be guessed from the speed.
func describeRoute(pcs []*webrtc.PeerConnection) string {
	type path struct{ local, remote string }
	kinds := []string{"direct", "TURN relay"}
	count := map[string]int{}
	paths := map[string][]path{}
	for _, pc := range pcs {
		if pc == nil || pc.SCTP() == nil || pc.SCTP().Transport() == nil || pc.SCTP().Transport().ICETransport() == nil {
			continue
		}
		pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		if err != nil || pair == nil || pair.Local == nil || pair.Remote == nil {
			continue
		}
		kind := kinds[0]
		if pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay {
			kind = kinds[1]
		}
		count[kind]++
		p := path{pair.Local.Address, pair.Remote.Address}
		seen := false
		for _, q := range paths[kind] {
			seen = seen || q == p
		}
		if !seen {
			paths[kind] = append(paths[kind], p)
		}
	}
	var parts []string
	for _, kind := range kinds {
		if count[kind] == 0 {
			continue
		}
		// One address pair is enough to recognise the network; the rest
		// are usually the same hosts over another address family.
		s := fmt.Sprintf("%s x%d (%s -> %s", kind, count[kind], paths[kind][0].local, paths[kind][0].remote)
		if extra := len(paths[kind]) - 1; extra > 0 {
			s += fmt.Sprintf(", +%d other address pair(s)", extra)
		}
		parts = append(parts, s+")")
	}
	if len(parts) == 0 {
		return ""
	}
	return "Route: " + strings.Join(parts, ", ")
}
