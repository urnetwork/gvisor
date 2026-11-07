// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Extends the existing manual-clock fixture without changing its constructors,
// clocks, timestamp offset, options, or timer settings. A late original echo
// retains the original flight's elapsed RTT; a second retry echo samples only
// that retry's flight, after both real exponential-backoff deadlines.
func privateCheckSynTimestampAdjacency(t *testing.T, passive, echoOriginal bool) {
	t.Helper()
	f := newPrivateSynTimestampFixture(t, privateSynTimestampCase{
		passive: passive, peerTimestamp: true, initialTimestamp: 10000,
	})
	f.ep.mu.Lock()
	defer f.ep.mu.Unlock()
	first := f.packet(t)
	expectedFlags := header.TCPFlagSyn
	if passive {
		expectedFlags |= header.TCPFlagAck
	}
	if first.flags != expectedFlags || !first.options.TS || first.options.TSVal == 0 {
		t.Fatalf("adjacent handshake wire premise: flags=%s options=%+v", first.flags, first.options)
	}
	cached := f.h.sendSYNOpts
	retryCount := 2
	if echoOriginal {
		retryCount = 1
	}
	last := first
	retryDelay := InitialRTO
	var transmitElapsed time.Duration
	timestampsFresh := true
	for retry := 0; retry < retryCount; retry++ {
		f.advance(retryDelay - time.Nanosecond)
		f.noPacket(t)
		f.advance(time.Nanosecond)
		last = f.packet(t)
		transmitElapsed += retryDelay
		firstOptions, lastOptions := first.options, last.options
		firstOptions.TSVal, lastOptions.TSVal = 0, 0
		if first.sequence != last.sequence || first.ack != last.ack || first.flags != last.flags || first.window != last.window || firstOptions != lastOptions || len(first.bytes) != len(last.bytes) || f.h.sendSYNOpts != cached || f.h.retransmitTimer.timeout != 2*retryDelay || !f.h.sampleRTTWithTSOnly {
			t.Fatalf("adjacent retry %d identity or timer changed", retry+1)
		}
		if last.options.TSVal == 0 || uint32(last.options.TSVal-first.options.TSVal) != uint32(transmitElapsed/time.Millisecond) {
			timestampsFresh = false
		}
		retryDelay *= 2
	}
	const networkRtt = 100 * time.Millisecond
	f.advance(networkRtt)
	echoed := last
	expectedRtt := networkRtt
	if echoOriginal {
		echoed = first
		expectedRtt += transmitElapsed
	}
	// reply copies TSEcr from this captured wire packet, including when the
	// final reply refers to the original transmission rather than a retry.
	f.reply(t, echoed, true)
	if f.ep.EndpointState() != StateEstablished || f.h.state != handshakeCompleted || !f.ep.SendTSOk {
		t.Fatalf("adjacent establishment premise: endpoint=%s handshake=%d negotiated=%t", f.ep.EndpointState(), f.h.state, f.ep.SendTSOk)
	}
	if f.h.active {
		ack := f.packet(t)
		if ack.flags != header.TCPFlagAck || ack.sequence != first.sequence+1 || ack.ack != 9001 {
			t.Fatal("adjacent final handshake ACK changed")
		}
	}
	f.noPacket(t)
	f.ep.snd.rtt.Lock()
	inited, srtt := f.ep.snd.rtt.SRTTInited, f.ep.snd.rtt.SRTT
	f.ep.snd.rtt.Unlock()
	rto := f.ep.snd.RTO
	// Cross the next retry deadline to check for later SYN emission. The
	// establishment path's timer stop is separate source evidence.
	f.advance(retryDelay + time.Nanosecond)
	f.noPacket(t)
	t.Logf("passive=%t retries=%d originalEcho=%t firstTS=%d lastTS=%d echoedTS=%d fresh=%t srttInited=%t srtt=%s rto=%s", passive, retryCount, echoOriginal, first.options.TSVal, last.options.TSVal, echoed.options.TSVal, timestampsFresh, inited, srtt, rto)
	if !echoOriginal && (!timestampsFresh || !inited || srtt != expectedRtt || rto != 3*expectedRtt) {
		t.Fatalf("SYN_RETRANSMIT_SECOND_TIMESTAMP_STALE: fresh=%t srtt=%s rto=%s; want srtt=%s rto=%s", timestampsFresh, srtt, rto, expectedRtt, 3*expectedRtt)
	}
	if echoOriginal && (!inited || srtt != expectedRtt || rto != 3*expectedRtt) {
		t.Fatalf("SYN_RETRANSMIT_ORIGINAL_ECHO_RTT_CHANGED: srtt=%s rto=%s; want srtt=%s rto=%s", srtt, rto, expectedRtt, 3*expectedRtt)
	}
}

// Both timed active retries must refresh TSVal, not just the first retry.
func TestPrivateSecondSynRetryTimestamp(t *testing.T) {
	privateCheckSynTimestampAdjacency(t, false, false)
}

// Both timed passive retries preserve the original negotiation and fresh TSVal.
func TestPrivateSecondSynAckRetryTimestamp(t *testing.T) {
	privateCheckSynTimestampAdjacency(t, true, false)
}

// A delayed original SYN-ACK still echoes the original active SYN timestamp.
func TestPrivateRetriedSynOriginalTimestampEcho(t *testing.T) {
	privateCheckSynTimestampAdjacency(t, false, true)
}

// A delayed final ACK can still echo the original passive SYN-ACK timestamp.
func TestPrivateRetriedSynAckOriginalTimestampEcho(t *testing.T) {
	privateCheckSynTimestampAdjacency(t, true, true)
}
