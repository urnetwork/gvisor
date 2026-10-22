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

// Private original-recovery-boundary witnesses against frozen V4. The existing
// endpoint/manual-clock fixture owns every real route packet and teardown.
// ACKs enter its normal segment queue; no loss, epoch, boundary or CC state is
// assigned by these witnesses.
package tcp

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// Held originals and all actual retransmissions remain endpoint-owned. The
// sequence/payload table identifies every possible data write without retaining
// an extra packet reference or fabricating a recovery owner.
type privateRackBoundaryFlight struct {
	first          seqnum.Value
	originalEnd    seqnum.Value
	newStart       seqnum.Value
	newEnd         seqnum.Value
	dataBySequence map[seqnum.Value][]byte
}

// Caller holds ep.mu. Actual old-flight delivery frees recovery slots, then
// actual source writes occupy them with newer sequence space beyond Last.
func privateRackPrepareBoundaryFlight(t *testing.T, c *ptoTestContext) (*privateRACKSafetyCC, privateRackBoundaryFlight) {
	t.Helper()
	s := c.ep.snd
	if _, ok := s.cc.(*renoState); !ok {
		t.Fatal("boundary witness requires the unchanged real Reno policy")
	}
	cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
	s.cc = cc
	first, oldData, suffix := privateRACKSuffixFlight(t, c)
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()))
	for index := range min(len(oldData), s.SndCwnd) {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), oldData[index])
	}
	c.expectNoPacket(t)
	if cc.lossCalls != 1 || cc.rtoCalls != 0 || s.rc.lossEpoch != 1 ||
		!s.FastRecovery.Active || s.SndCwnd != 10 || s.FastRecovery.Last+1 != suffix.End {
		t.Fatalf("initial recovery premise: responses=%d RTOs=%d epoch=%d active=%t cwnd=%d Last=%d originalEnd=%d",
			cc.lossCalls, cc.rtoCalls, s.rc.lossEpoch, s.FastRecovery.Active, s.SndCwnd, s.FastRecovery.Last, suffix.End)
	}

	// All old original copies were physically emitted. Deliver every one
	// except the missing head, including late originals not yet replayed.
	privateRACKSuffixACK(t, c, first, header.SACKBlock{
		Start: first.Add(ptoTestPayloadSize),
		End:   suffix.End,
	})
	c.expectNoPacket(t)
	if cc.lossCalls != 1 || s.rc.lossEpoch != 1 || !s.FastRecovery.Active ||
		s.Outstanding != 1 || !s.rc.Reord {
		t.Fatalf("old SACK did not leave exactly one genuine protected head: responses=%d epoch=%d active=%t pipe=%d reordered=%t",
			cc.lossCalls, s.rc.lossEpoch, s.FastRecovery.Active, s.Outstanding, s.rc.Reord)
	}

	flight := privateRackBoundaryFlight{
		first: first, originalEnd: suffix.End,
		newStart: s.SndNxt, dataBySequence: make(map[seqnum.Value][]byte),
	}
	for index, data := range oldData {
		flight.dataBySequence[first.Add(seqnum.Size(index*ptoTestPayloadSize))] = data
	}
	flight.dataBySequence[suffix.Start] = bytes.Repeat([]byte{0xee}, 258)
	for index := range 9 {
		size := ptoTestPayloadSize
		if index == 8 {
			size = 258
		}
		data := bytes.Repeat([]byte{byte(0xa0 + index)}, size)
		sequence := s.SndNxt
		flight.dataBySequence[sequence] = data
		c.write(data)
		c.expectPacket(t, sequence, data)
	}
	c.expectNoPacket(t)
	flight.newEnd = s.SndNxt
	if flight.newStart != flight.originalEnd || !s.FastRecovery.Last.LessThan(flight.newStart) ||
		s.FastRecovery.Last+1 != flight.originalEnd || s.Outstanding != 10 ||
		cc.lossCalls != 1 || s.rc.lossEpoch != 1 {
		t.Fatalf("actual new-flight premise: newStart=%d newEnd=%d originalEnd=%d Last=%d pipe=%d responses=%d epoch=%d",
			flight.newStart, flight.newEnd, flight.originalEnd, s.FastRecovery.Last, s.Outstanding, cc.lossCalls, s.rc.lossEpoch)
	}
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if !seg.sequenceNumber.LessThan(flight.newStart) && (seg.xmitCount != 1 || seg.lost || seg.lossEpoch != 1) {
			t.Fatal("actual beyond-Last flight lacks fresh current-epoch physical custody")
		}
	}
	return cc, flight
}

// Snapshot only scalar identities; the endpoint retains every packet.
func privateRackBoundarySnapshot(c *ptoTestContext) map[seqnum.Value]uint32 {
	before := make(map[seqnum.Value]uint32)
	for seg := c.ep.snd.writeList.Front(); seg != nil; seg = seg.Next() {
		before[seg.sequenceNumber] = seg.xmitCount
	}
	return before
}

// Caller holds ep.mu. Consume and validate every actual wire write in the
// sender's dispatch order, including an unexpected forced first replay.
func privateRackBoundaryTakeWrites(t *testing.T, c *ptoTestContext, flight privateRackBoundaryFlight, before map[seqnum.Value]uint32) []seqnum.Value {
	t.Helper()
	var writes []seqnum.Value
	for seg := c.ep.snd.writeList.Front(); seg != nil; seg = seg.Next() {
		count, ok := before[seg.sequenceNumber]
		if !ok || seg.xmitCount < count || seg.xmitCount > count+1 {
			t.Fatalf("unexpected retained transmission mutation: seq=%d before=%d found=%t after=%d",
				seg.sequenceNumber, count, ok, seg.xmitCount)
		}
		if seg.xmitCount == count {
			continue
		}
		data, ok := flight.dataBySequence[seg.sequenceNumber]
		if !ok {
			t.Fatalf("write has no actual emitted payload identity: seq=%d", seg.sequenceNumber)
		}
		c.expectPacket(t, seg.sequenceNumber, data)
		writes = append(writes, seg.sequenceNumber)
	}
	c.expectNoPacket(t)
	return writes
}

// Actual suffix feedback follows the prior replay by one RTT. Genuine late
// old-original delivery established reordering, so only the real pending
// reorder timer may classify these new losses; no timer is shortened.
func privateRackBoundaryExpireNewLoss(t *testing.T, c *ptoTestContext, cc *privateRACKSafetyCC, flight privateRackBoundaryFlight) {
	t.Helper()
	c.advance(100 * time.Millisecond)
	c.expectNoPacket(t)
	privateRACKSuffixACK(t, c, c.ep.snd.SndUna, header.SACKBlock{
		Start: flight.newEnd - 258,
		End:   flight.newEnd,
	})
	c.expectNoPacket(t)
	s := c.ep.snd
	if cc.lossCalls != 1 || !s.reorderTimer.enabled() || !c.clock.NowMonotonic().Before(s.reorderTimer.target) {
		t.Fatalf("new-flight loss was not deferred to actual reorder deadline: responses=%d active=%t reordered=%t reo=%s timer=%t now=%s target=%s",
			cc.lossCalls, s.FastRecovery.Active, s.rc.Reord, s.rc.ReoWnd, s.reorderTimer.enabled(), c.clock.NowMonotonic(), s.reorderTimer.target)
	}
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()))
}

// Crossing the original Last must not charge still-pending, already-accounted
// later loss twice. Repair progress remains mandatory when the ACK frees one
// slot; merely suppressing recovery re-entry is not an acceptable correction.
func TestRackChargedLossCrossesOriginalRecoveryBoundary(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	cc, flight := privateRackPrepareBoundaryFlight(t, c)
	s := c.ep.snd
	beforeLoss := privateRackBoundarySnapshot(c)
	privateRackBoundaryExpireNewLoss(t, c, cc, flight)
	repairs := privateRackBoundaryTakeWrites(t, c, flight, beforeLoss)
	if cc.lossCalls != 2 || cc.rtoCalls != 0 || s.rc.lossEpoch != 2 ||
		!s.FastRecovery.Active || s.SndCwnd != 4 || s.Outstanding != 4 || len(repairs) != 4 {
		t.Fatalf("second response premise: responses=%d RTOs=%d epoch=%d active=%t cwnd=%d pipe=%d writes=%v",
			cc.lossCalls, cc.rtoCalls, s.rc.lossEpoch, s.FastRecovery.Active, s.SndCwnd, s.Outstanding, repairs)
	}
	pending := 0
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if !seg.sequenceNumber.LessThan(flight.newStart) && seg.lost {
			if seg.lossEpoch != 1 || seg.xmitCount != 1 {
				t.Fatal("pending later loss was not already charged to the preceding send epoch")
			}
			pending++
		}
	}
	if pending != 5 || repairs[0] != flight.first || repairs[1] != flight.newStart {
		t.Fatalf("later pending-loss geometry: pending=%d writes=%v", pending, repairs)
	}

	// This ACK completes only the old recovery prefix, not newer holes.
	// It arrives at the same clock instant; no newer send can time out.
	beforeBoundary := privateRackBoundarySnapshot(c)
	epoch, responses, cwnd := s.rc.lossEpoch, cc.lossCalls, s.SndCwnd
	recoveryBefore := s.FastRecovery
	c.receive(t, flight.originalEnd, s.SndWnd, nil)
	writes := privateRackBoundaryTakeWrites(t, c, flight, beforeBoundary)
	t.Logf("original_Last_crossing: originalEnd=%d newEnd=%d before_Last=%d after_Last=%d before_epoch=%d after_epoch=%d before_responses=%d after_responses=%d before_cwnd=%d after_cwnd=%d pipe=%d actual_writes=%v pending_charged=%d",
		flight.originalEnd, flight.newEnd, recoveryBefore.Last, s.FastRecovery.Last, epoch, s.rc.lossEpoch, responses, cc.lossCalls, cwnd, s.SndCwnd, s.Outstanding, writes, pending)
	if cc.lossCalls != responses || s.rc.lossEpoch != epoch {
		t.Fatalf("RACK_CHARGED_LOSS_COUNTED_AGAIN_AT_ORIGINAL_LAST: responses=%d->%d epoch=%d->%d old_Last=%d ack=%d newEnd=%d actual_writes=%v; no new false-to-true loss or clock advance",
			responses, cc.lossCalls, epoch, s.rc.lossEpoch, recoveryBefore.Last, flight.originalEnd, flight.newEnd, writes)
	}
	if s.SndUna != flight.originalEnd || s.SndCwnd != cwnd || s.Outstanding != cwnd ||
		len(writes) != 1 || writes[0] != flight.newStart.Add(3*ptoTestPayloadSize) ||
		c.ep.stack.Stats().TCP.FastRetransmit.Value() != 1 || cc.rtoCalls != 0 {
		t.Fatalf("ACK-freed capacity failed real already-charged loss repair: una=%d cwnd=%d pipe=%d writes=%v forced=%d RTOs=%d",
			s.SndUna, s.SndCwnd, s.Outstanding, writes, c.ep.stack.Stats().TCP.FastRetransmit.Value(), cc.rtoCalls)
	}
	// Deliver all previously emitted held copies and retire the exact queue.
	c.receive(t, flight.newEnd, s.SndWnd, nil)
	c.expectNoPacket(t)
	if s.SndUna != flight.newEnd || s.Outstanding != 0 || s.writeList.Front() != nil || cc.lossCalls != 2 || cc.rtoCalls != 0 {
		t.Fatal("completed actual later flight did not release all send custody")
	}
}

// An uncharged later window must still produce a genuine congestion response
// after the original recovery finishes; an inactive-epoch blanket refusal
// would pass the negative case while stranding this real newer loss.
func TestRackNewLossAfterOriginalRecoveryBoundaryStillResponds(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	cc, flight := privateRackPrepareBoundaryFlight(t, c)
	s := c.ep.snd
	c.receive(t, flight.originalEnd, s.SndWnd, nil)
	c.expectNoPacket(t)
	if s.FastRecovery.Active || cc.lossCalls != 1 || s.rc.lossEpoch != 1 || s.SndUna != flight.originalEnd {
		t.Fatalf("completed original-prefix control: active=%t responses=%d epoch=%d una=%d",
			s.FastRecovery.Active, cc.lossCalls, s.rc.lossEpoch, s.SndUna)
	}
	beforeLoss := privateRackBoundarySnapshot(c)
	privateRackBoundaryExpireNewLoss(t, c, cc, flight)
	writes := privateRackBoundaryTakeWrites(t, c, flight, beforeLoss)
	if cc.lossCalls != 2 || cc.rtoCalls != 0 || s.rc.lossEpoch != 2 ||
		!s.FastRecovery.Active || s.FastRecovery.Last+1 != flight.newEnd || len(writes) == 0 ||
		len(writes) != s.Outstanding || len(writes) > s.SndCwnd ||
		c.ep.stack.Stats().TCP.FastRetransmit.Value() != 2 {
		t.Fatalf("genuine newer inactive-window loss did not respond and repair: responses=%d RTOs=%d epoch=%d active=%t Last=%d newEnd=%d cwnd=%d pipe=%d writes=%v forced=%d",
			cc.lossCalls, cc.rtoCalls, s.rc.lossEpoch, s.FastRecovery.Active, s.FastRecovery.Last, flight.newEnd, s.SndCwnd, s.Outstanding, writes, c.ep.stack.Stats().TCP.FastRetransmit.Value())
	}
	c.receive(t, flight.newEnd, s.SndWnd, nil)
	c.expectNoPacket(t)
	if s.Outstanding != 0 || s.writeList.Front() != nil || cc.lossCalls != 2 || cc.rtoCalls != 0 {
		t.Fatal("genuine later-window completion retained a send owner or extra response")
	}
}
