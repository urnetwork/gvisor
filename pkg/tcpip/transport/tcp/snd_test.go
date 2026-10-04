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
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const ptoTestPayloadSize = 1000

// ptoTestContext uses a real sender, receiver, and output route. Receive work is
// processed synchronously, and only advancing the manual clock runs timers, so
// packet and deadline assertions need neither sleeps nor polling.
type ptoTestContext struct {
	ep    *Endpoint
	clock *faketime.ManualClock
	link  *channel.Endpoint
}

func newPTOTestContext(t *testing.T) *ptoTestContext {
	t.Helper()
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		Clock:              clock,
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	t.Cleanup(s.Destroy)
	link := channel.New(16, 1500, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	localAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 1})
	remoteAddr := tcpip.AddrFrom4([4]byte{192, 0, 2, 2})
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: localAddr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	route, err := s.FindRoute(1, localAddr, remoteAddr, ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		t.Fatalf("FindRoute: %s", err)
	}
	ep := newEndpoint(s, protocolFromStack(s), ipv4.ProtocolNumber, &waiter.Queue{})
	t.Cleanup(ep.Abort)
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.route = route
	ep.ID = stack.TransportEndpointID{
		LocalAddress:  localAddr,
		LocalPort:     1234,
		RemoteAddress: remoteAddr,
		RemotePort:    4321,
	}
	ep.SACKPermitted = true
	ep.tcpRecovery = tcpip.TCPRACKLossDetection
	ep.setEndpointState(StateEstablished)
	ep.rcv = newReceiver(ep, 2000, 65535, 0)
	initSender(ep, 1000, 2000, 65535, uint16(ptoTestPayloadSize+ep.maxOptionSize()), 0)
	ep.snd.rtt.Lock()
	ep.snd.rtt.SRTTInited = true
	ep.snd.rtt.SRTT = 100 * time.Millisecond
	ep.snd.rtt.Unlock()
	return &ptoTestContext{ep: ep, clock: clock, link: link}
}

// advance lets the production timer callbacks acquire the endpoint lock. The
// manual clock waits for those callbacks to finish before returning.
//
// +checklocks:c.ep.mu
func (c *ptoTestContext) advance(d time.Duration) {
	c.ep.mu.Unlock()
	c.clock.Advance(d)
	c.ep.mu.Lock()
}

// +checklocks:c.ep.mu
func (c *ptoTestContext) write(data []byte) {
	s := newOutgoingSegment(c.ep.ID, c.clock, buffer.MakeWithData(bytes.Clone(data)), 0)
	s.setOwner(c.ep, sendQ)
	c.ep.sndQueueInfo.sndQueueMu.Lock()
	c.ep.sndQueueInfo.SndBufUsed += len(data)
	c.ep.sndQueueInfo.sndQueueMu.Unlock()
	c.ep.snd.writeList.PushBack(s)
	c.ep.sendData(s)
}

// +checklocks:c.ep.mu
func (c *ptoTestContext) receive(t *testing.T, ack seqnum.Value, window seqnum.Size, data []byte) {
	t.Helper()
	s := newOutgoingSegment(c.ep.ID, c.clock, buffer.MakeWithData(bytes.Clone(data)), 0)
	defer s.DecRef()
	s.sequenceNumber = c.ep.rcv.RcvNxt
	s.ackNumber = ack
	s.window = window
	s.flags = header.TCPFlagAck
	if !c.ep.segmentQueue.enqueue(s) {
		t.Fatal("failed to enqueue incoming segment")
	}
	if err := c.ep.handleSegmentsLocked(); err != nil {
		t.Fatalf("handleSegmentsLocked: %s", err)
	}
}

func (c *ptoTestContext) expectPacket(t *testing.T, seq seqnum.Value, data []byte) {
	t.Helper()
	pkt := c.link.Read()
	if pkt == nil {
		t.Fatalf("no packet at %s; want seq=%d, payload length=%d", c.clock.NowMonotonic(), seq, len(data))
	}
	defer pkt.DecRef()
	h := header.TCP(pkt.TransportHeader().Slice())
	if got := h.SequenceNumber(); got != uint32(seq) {
		t.Errorf("packet sequence = %d, want %d", got, seq)
	}
	if !h.Flags().Contains(header.TCPFlagAck) {
		t.Errorf("packet flags = %s, want ACK", h.Flags())
	}
	v := pkt.Data().AsRange().ToView()
	if v != nil {
		defer v.Release()
	}
	if got := v.AsSlice(); !bytes.Equal(got, data) {
		t.Fatalf("packet payload = (%d bytes) %.16x..., want (%d bytes) %.16x...", len(got), got, len(data), data)
	}
}

func (c *ptoTestContext) expectNoPacket(t *testing.T) {
	t.Helper()
	if pkt := c.link.Read(); pkt != nil {
		defer pkt.DecRef()
		h := header.TCP(pkt.TransportHeader().Slice())
		t.Fatalf("unexpected packet at %s: seq=%d, payload length=%d", c.clock.NowMonotonic(), h.SequenceNumber(), pkt.Data().Size())
	}
}

// Nonadvancing traffic used to call sendData -> postXmit -> schedulePTO even
// when nothing was sent. Each packet moved the probe deadline into the future,
// while the resend timer remained disabled, so a busy reverse direction could
// prevent both TLP and RTO recovery indefinitely.
func TestPTONonAdvancingTraffic(t *testing.T) {
	for _, traffic := range []struct {
		name string
		data []byte
	}{
		{name: "DuplicateACK"},
		{name: "ReversePayload", data: []byte("reverse traffic")},
	} {
		for _, blocked := range []string{"EmptySendQueue", "CongestionWindowFull", "SendWindowFull"} {
			t.Run(traffic.name+"/"+blocked, func(t *testing.T) {
				c := newPTOTestContext(t)
				ep := c.ep
				ep.mu.Lock()
				defer ep.mu.Unlock()
				s := ep.snd
				seq := s.SndNxt
				data := bytes.Repeat([]byte{0xab}, ptoTestPayloadSize)
				c.write(data)
				// Discard the original transmission and all subsequent probes.
				c.expectPacket(t, seq, data)
				switch blocked {
				case "CongestionWindowFull":
					s.SndCwnd = s.Outstanding
					c.write(bytes.Repeat([]byte{0xcd}, ptoTestPayloadSize))
				case "SendWindowFull":
					s.SndWnd = ptoTestPayloadSize
					c.write(bytes.Repeat([]byte{0xcd}, ptoTestPayloadSize))
				}
				c.expectNoPacket(t)
				// One segment in flight: 2*SRTT + the delayed ACK allowance.
				const pto = 400 * time.Millisecond
				deadline := c.clock.NowMonotonic().Add(pto)
				if !s.probeTimer.enabled() || s.probeTimer.target != deadline || s.resendTimer.enabled() {
					t.Fatalf("initial timers: PTO enabled=%t target=%s, RTO enabled=%t; want PTO at %s only", s.probeTimer.enabled(), s.probeTimer.target, s.resendTimer.enabled(), deadline)
				}

				receive := func() {
					t.Helper()
					c.receive(t, seq, s.SndWnd, traffic.data)
					if len(traffic.data) != 0 {
						c.expectPacket(t, s.SndNxt, nil) // ACK the reverse payload.
					}
					c.expectNoPacket(t)
					if s.SndUna != seq || s.SndNxt != seq.Add(ptoTestPayloadSize) || s.Outstanding != 1 {
						t.Fatalf("nonadvancing traffic changed flight: una=%d nxt=%d outstanding=%d", s.SndUna, s.SndNxt, s.Outstanding)
					}
				}
				for i := 0; i < 3; i++ {
					c.advance(pto / 4)
					receive()
					if !s.probeTimer.enabled() || s.probeTimer.target != deadline || s.resendTimer.enabled() {
						t.Errorf("after nonadvancing traffic at %s: PTO enabled=%t target=%s, RTO enabled=%t; want original PTO at %s only", c.clock.NowMonotonic(), s.probeTimer.enabled(), s.probeTimer.target, s.resendTimer.enabled(), deadline)
					}
				}
				c.advance(pto/4 - time.Nanosecond)
				c.expectNoPacket(t)
				c.advance(time.Nanosecond)
				c.expectPacket(t, seq, data)
				c.expectNoPacket(t)
				if !s.rc.tlpRxtOut || s.probeTimer.enabled() || !s.resendTimer.enabled() {
					t.Fatalf("probe did not hand off to RTO: tlpRxtOut=%t PTO enabled=%t RTO enabled=%t", s.rc.tlpRxtOut, s.probeTimer.enabled(), s.resendTimer.enabled())
				}

				// If the probe is also lost, ongoing reverse traffic must leave
				// the fallback RTO armed, rather than replacing it with a new PTO.
				rto := s.RTO
				rtoDeadline := c.clock.NowMonotonic().Add(rto)
				for i := 0; i < 9; i++ {
					c.advance(rto / 10)
					receive()
					if s.probeTimer.enabled() || !s.resendTimer.enabled() || s.resendTimer.target != rtoDeadline {
						t.Errorf("after nonadvancing traffic at %s: PTO enabled=%t, RTO enabled=%t target=%s; want RTO at %s only", c.clock.NowMonotonic(), s.probeTimer.enabled(), s.resendTimer.enabled(), s.resendTimer.target, rtoDeadline)
					}
				}
				c.advance(rto/10 - time.Nanosecond)
				c.expectNoPacket(t)
				c.advance(time.Nanosecond)
				c.expectPacket(t, seq, data)
				c.expectNoPacket(t)
				if s.state != tcpip.RTORecovery || ep.stack.Stats().TCP.Timeouts.Value() != 1 {
					t.Fatalf("did not enter RTO recovery: state=%v timeouts=%d", s.state, ep.stack.Stats().TCP.Timeouts.Value())
				}
			})
		}
	}
}

func TestPTORearmedAfterProgress(t *testing.T) {
	for _, progress := range []string{"NewData", "CumulativeACK"} {
		t.Run(progress, func(t *testing.T) {
			c := newPTOTestContext(t)
			ep := c.ep
			ep.mu.Lock()
			defer ep.mu.Unlock()
			s := ep.snd
			seq := s.SndNxt
			data := bytes.Repeat([]byte{0xab}, ptoTestPayloadSize)
			for i := 0; i < 3; i++ {
				c.write(data)
				c.expectPacket(t, seq.Add(seqnum.Size(i*ptoTestPayloadSize)), data)
			}
			oldDeadline := s.probeTimer.target
			c.advance(100 * time.Millisecond)
			lastSeq := seq.Add(2 * ptoTestPayloadSize)
			switch progress {
			case "NewData":
				lastSeq = s.SndNxt
				c.write(data)
				c.expectPacket(t, lastSeq, data)
			case "CumulativeACK":
				c.receive(t, seq.Add(ptoTestPayloadSize), s.SndWnd, nil)
				if s.SndUna != seq.Add(ptoTestPayloadSize) || s.Outstanding != 2 {
					t.Fatalf("cumulative ACK did not advance flight: una=%d outstanding=%d", s.SndUna, s.Outstanding)
				}
			}
			c.expectNoPacket(t)
			// The ACK's RTT sample is also 100ms, so SRTT remains unchanged.
			deadline := c.clock.NowMonotonic().Add(200 * time.Millisecond)
			if !s.probeTimer.enabled() || s.probeTimer.target != deadline || !oldDeadline.Before(deadline) || s.resendTimer.enabled() {
				t.Fatalf("progress did not rearm PTO: enabled=%t target=%s RTO enabled=%t; want PTO at %s only", s.probeTimer.enabled(), s.probeTimer.target, s.resendTimer.enabled(), deadline)
			}
			c.advance(oldDeadline.Sub(c.clock.NowMonotonic()))
			c.expectNoPacket(t)
			c.advance(deadline.Sub(c.clock.NowMonotonic()) - time.Nanosecond)
			c.expectNoPacket(t)
			c.advance(time.Nanosecond)
			c.expectPacket(t, lastSeq, data)
			c.expectNoPacket(t)
		})
	}
}

func TestPTOBlockedProbeArmsRTO(t *testing.T) {
	c := newPTOTestContext(t)
	ep := c.ep
	ep.mu.Lock()
	defer ep.mu.Unlock()
	s := ep.snd
	seq := s.SndNxt
	data := bytes.Repeat([]byte{0xab}, ptoTestPayloadSize)
	c.write(data)
	c.expectPacket(t, seq, data)
	// Closing the peer's window prevents the probe from transmitting. Even
	// without a transmission, probe expiry must still arm the resend timer.
	c.receive(t, seq, 0, nil)
	c.advance(400 * time.Millisecond)
	c.expectNoPacket(t)
	if s.rc.tlpRxtOut || s.probeTimer.enabled() || !s.resendTimer.enabled() {
		t.Fatalf("blocked probe did not arm RTO: tlpRxtOut=%t PTO enabled=%t RTO enabled=%t", s.rc.tlpRxtOut, s.probeTimer.enabled(), s.resendTimer.enabled())
	}
	if got, want := s.resendTimer.target, c.clock.NowMonotonic().Add(s.RTO); got != want {
		t.Errorf("RTO deadline = %s, want %s", got, want)
	}
}
