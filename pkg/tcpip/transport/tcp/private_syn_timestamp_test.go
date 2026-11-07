// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	internaltcp "gvisor.dev/gvisor/pkg/tcpip/internal/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Owns the real handshake, route, packet channel and manual timer. Incoming
// replies use the wire parser and handshake queue; no socket or wall clock runs.
type privateSynTimestampFixture struct {
	ep    *Endpoint
	h     *handshake
	clock *faketime.ManualClock
	link  *channel.Endpoint
}

// Keeps each scenario explicit without changing any TCP timer or RTO setting.
type privateSynTimestampCase struct {
	passive          bool
	peerTimestamp    bool
	dropFirst        bool
	initialTimestamp uint32
}

// Holds only copied wire scalars and bytes, after the packet reference returns.
type privateSynTimestampPacket struct {
	sequence uint32
	ack      uint32
	flags    header.TCPFlags
	window   uint16
	options  header.TCPSynOptions
	bytes    []byte
}

// Starts the same active/passive state machine as Connect/listen, with a fixed
// test timestamp offset installed before its first send (never mid-flight).
func newPrivateSynTimestampFixture(t *testing.T, testCase privateSynTimestampCase) *privateSynTimestampFixture {
	t.Helper()
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		Clock:              clock,
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	t.Cleanup(s.Destroy)
	link := channel.New(16, 1500, "")
	t.Cleanup(link.Close)
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	local := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	remote := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber, AddressWithPrefix: local.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	route, err := s.FindRoute(1, local, remote, ipv4.ProtocolNumber, false)
	if err != nil {
		t.Fatalf("FindRoute: %s", err)
	}
	ep := newEndpoint(s, protocolFromStack(s), ipv4.ProtocolNumber, &waiter.Queue{})
	t.Cleanup(ep.Abort)
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.route = route
	ep.ID = stack.TransportEndpointID{LocalAddress: local, LocalPort: 1234, RemoteAddress: remote, RemotePort: 4321}
	var h *handshake
	if testCase.passive {
		peerOptions := header.TCPSynOptions{MSS: 1460, WS: 2, TS: testCase.peerTimestamp, TSVal: 5000, SACKPermitted: true}
		ep.maybeEnableTimestamp(peerOptions)
		ep.maybeEnableSACKPermitted(peerOptions)
		h = ep.newPassiveHandshake(1000, 9000, peerOptions, 0)
	} else {
		h = ep.newHandshake()
		ep.setEndpointState(StateSynSent)
	}
	// newHandshake initializes its own offset. This deterministic replacement
	// precedes the original SYN and stays fixed through the complete exchange.
	ep.TSOffset = internaltcp.NewTSOffset(testCase.initialTimestamp)
	h.start()
	return &privateSynTimestampFixture{ep: ep, h: h, clock: clock, link: link}
}

// Allows only the production timer callback to acquire the endpoint mutex;
// Advance joins all callbacks before returning.
func (self *privateSynTimestampFixture) advance(d time.Duration) {
	self.ep.mu.Unlock()
	self.clock.Advance(d)
	self.ep.mu.Lock()
}

// Copies an emitted TCP header and returns its packet owner immediately.
func (self *privateSynTimestampFixture) packet(t *testing.T) privateSynTimestampPacket {
	t.Helper()
	pkt := self.link.Read()
	if pkt == nil {
		t.Fatalf("SYN_TIMESTAMP_PACKET_MISSING at %s", self.clock.NowMonotonic())
	}
	defer pkt.DecRef()
	h := header.TCP(pkt.TransportHeader().Slice())
	if pkt.Data().Size() != 0 {
		t.Fatal("handshake unexpectedly sent data")
	}
	return privateSynTimestampPacket{
		sequence: h.SequenceNumber(), ack: h.AckNumber(), flags: h.Flags(), window: h.WindowSize(),
		options: header.ParseSynOptions(h.Options(), h.Flags().Contains(header.TCPFlagAck)), bytes: bytes.Clone(h),
	}
}

// A missing packet is checked at the exact manual-clock boundary, without polls.
func (self *privateSynTimestampFixture) noPacket(t *testing.T) {
	t.Helper()
	if pkt := self.link.Read(); pkt != nil {
		defer pkt.DecRef()
		t.Fatalf("unexpected handshake packet at %s", self.clock.NowMonotonic())
	}
}

// Echoes the timestamp from the actually emitted packet through the production
// TCP option parser and handshake queue. The initial dropped packet is not ACKed.
func (self *privateSynTimestampFixture) reply(t *testing.T, sent privateSynTimestampPacket, peerTimestamp bool) {
	t.Helper()
	flags, sequence := header.TCPFlagSyn|header.TCPFlagAck, uint32(9000)
	var options []byte
	if self.h.active {
		pooled := makeSynOptions(header.TCPSynOptions{MSS: 1460, WS: 2, TS: peerTimestamp, TSVal: 7000, TSEcr: sent.options.TSVal, SACKPermitted: true})
		options = bytes.Clone(pooled)
		putOptions(pooled)
	} else {
		flags, sequence = header.TCPFlagAck, uint32(9001)
		if peerTimestamp {
			options = make([]byte, 12)
			options[0], options[1] = header.TCPOptionNOP, header.TCPOptionNOP
			header.EncodeTSOption(7000, sent.options.TSVal, options[2:])
		}
	}
	tcpLength := header.TCPMinimumSize + len(options)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize + tcpLength})
	defer pkt.DecRef()
	tcpHeader := header.TCP(pkt.TransportHeader().Push(tcpLength))
	tcpHeader.Encode(&header.TCPFields{
		SrcPort: self.ep.ID.RemotePort, DstPort: self.ep.ID.LocalPort,
		SeqNum: sequence, AckNum: sent.sequence + 1, DataOffset: uint8(tcpLength), Flags: flags, WindowSize: 65535,
	})
	copy(tcpHeader[header.TCPMinimumSize:], options)
	ipHeader := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHeader.Encode(&header.IPv4Fields{TotalLength: uint16(header.IPv4MinimumSize + tcpLength), TTL: 64, Protocol: uint8(ProtocolNumber), SrcAddr: self.ep.ID.RemoteAddress, DstAddr: self.ep.ID.LocalAddress})
	pkt.NetworkProtocolNumber = ipv4.ProtocolNumber
	pkt.RXChecksumValidated = true
	s, err := newIncomingSegment(self.ep.ID, self.clock, pkt)
	if err != nil {
		t.Fatalf("newIncomingSegment: %s", err)
	}
	defer s.DecRef()
	if !self.ep.segmentQueue.enqueue(s) {
		t.Fatal("handshake reply queue refused")
	}
	if err := self.h.processSegments(); err != nil {
		t.Fatalf("processSegments: %s", err)
	}
}

// Checks both the transmitted timestamp and the resulting sender estimator;
// old code reaches ESTABLISHED before reporting its typed causal failure.
func privateCheckSynTimestamp(t *testing.T, testCase privateSynTimestampCase) {
	t.Helper()
	f := newPrivateSynTimestampFixture(t, testCase)
	f.ep.mu.Lock()
	defer f.ep.mu.Unlock()
	first := f.packet(t)
	expectedFlags := header.TCPFlagSyn
	if testCase.passive {
		expectedFlags |= header.TCPFlagAck
	}
	if first.flags != expectedFlags || first.options.TS != (!testCase.passive || testCase.peerTimestamp) {
		t.Fatalf("handshake wire premise: flags=%s options=%+v", first.flags, first.options)
	}
	cached := f.h.sendSYNOpts
	last := first
	if testCase.dropFirst {
		f.advance(InitialRTO - time.Nanosecond)
		f.noPacket(t)
		f.advance(time.Nanosecond)
		last = f.packet(t)
		firstOptions, lastOptions := first.options, last.options
		firstOptions.TSVal, lastOptions.TSVal = 0, 0
		if first.sequence != last.sequence || first.ack != last.ack || first.flags != last.flags || first.window != last.window || firstOptions != lastOptions || len(first.bytes) != len(last.bytes) || f.h.sendSYNOpts != cached || f.h.retransmitTimer.timeout != 2*InitialRTO || !f.h.sampleRTTWithTSOnly {
			t.Fatal("SYN_TIMESTAMP_RETRY_IDENTITY_OR_TIMER_CHANGED")
		}
		if !first.options.TS && !bytes.Equal(first.bytes, last.bytes) {
			t.Fatal("timestamp-disabled SYN bytes changed")
		}
	}
	const networkRtt = 100 * time.Millisecond
	f.advance(networkRtt)
	f.reply(t, last, testCase.peerTimestamp)
	if f.ep.EndpointState() != StateEstablished || f.h.state != handshakeCompleted || f.ep.SendTSOk != testCase.peerTimestamp {
		t.Fatalf("SYN_TIMESTAMP_ESTABLISHMENT_PREMISE: endpoint=%s handshake=%d negotiated=%t", f.ep.EndpointState(), f.h.state, f.ep.SendTSOk)
	}
	if f.h.active {
		ack := f.packet(t)
		if ack.flags != header.TCPFlagAck || ack.sequence != last.sequence+1 || ack.ack != 9001 {
			t.Fatal("final handshake ACK changed")
		}
	}
	f.noPacket(t)
	f.ep.snd.rtt.Lock()
	inited, srtt := f.ep.snd.rtt.SRTTInited, f.ep.snd.rtt.SRTT
	f.ep.snd.rtt.Unlock()
	rto := f.ep.snd.RTO
	// Advancing beyond the next unchanged retry deadline proves no later SYN
	// emission. The unchanged establishment path explicitly stops the timer.
	f.advance(2*InitialRTO + time.Nanosecond)
	f.noPacket(t)
	t.Logf("passive=%t peerTS=%t dropped=%t firstTS=%d retryTS=%d deltaMS=%d srttInited=%t srtt=%s rto=%s", testCase.passive, testCase.peerTimestamp, testCase.dropFirst, first.options.TSVal, last.options.TSVal, uint32(last.options.TSVal-first.options.TSVal), inited, srtt, rto)
	if testCase.dropFirst && testCase.peerTimestamp {
		if uint32(last.options.TSVal-first.options.TSVal) != uint32(InitialRTO/time.Millisecond) || last.options.TSVal == 0 || !inited || srtt != networkRtt || rto != 3*networkRtt {
			t.Fatalf("SYN_RETRANSMIT_TIMESTAMP_STALE: deltaMS=%d srtt=%s rto=%s; want retry delta=%dms, srtt=%s, rto=%s", uint32(last.options.TSVal-first.options.TSVal), srtt, rto, InitialRTO/time.Millisecond, networkRtt, 3*networkRtt)
		}
	} else if testCase.dropFirst {
		if inited || rto != InitialRTO {
			t.Fatalf("Karn no-timestamp retry changed: inited=%t rto=%s", inited, rto)
		}
	} else if !inited || srtt != networkRtt || rto != 3*networkRtt {
		t.Fatalf("clean handshake RTT changed: inited=%t srtt=%s rto=%s", inited, srtt, rto)
	}
}

// The dropped original is read and discarded; only its timed retry is echoed.
func TestPrivateDroppedSynTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{peerTimestamp: true, dropFirst: true, initialTimestamp: 10000})
}

// Timestamp arithmetic must remain correct when the retry crosses uint32 wrap.
func TestPrivateDroppedSynTimestampWrap(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{peerTimestamp: true, dropFirst: true, initialTimestamp: ^uint32(0) - 499})
}

// Clean active timestamp negotiation continues to sample only network RTT.
func TestPrivateCleanSynTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{peerTimestamp: true, initialTimestamp: 10000})
}

// Without retry, peers declining timestamps retain the ordinary handshake RTT.
func TestPrivateCleanSynNoTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{initialTimestamp: 10000})
}

// A retry without negotiated timestamps must retain Karn's no-sample behavior.
func TestPrivateRetriedSynNoTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{dropFirst: true, initialTimestamp: 10000})
}

// Passive SYN-ACK retransmission uses the same timestamp contract and timer.
func TestPrivateDroppedSynAckTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{passive: true, peerTimestamp: true, dropFirst: true, initialTimestamp: 10000})
}

// Passive clean completion continues to accept its timestamp-bearing final ACK.
func TestPrivateCleanSynAckTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{passive: true, peerTimestamp: true, initialTimestamp: 10000})
}

// Passive timestamp-disabled retries preserve exact bytes and no RTT sample.
func TestPrivateRetriedSynAckNoTimestamp(t *testing.T) {
	privateCheckSynTimestamp(t, privateSynTimestampCase{passive: true, dropFirst: true, initialTimestamp: 10000})
}
