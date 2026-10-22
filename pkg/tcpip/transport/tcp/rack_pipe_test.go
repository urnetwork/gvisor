// Private deterministic RACK/pipe witness. No transport timers or production
// defaults are changed; the existing real-endpoint/manual-clock fixture owns
// all packets, timers, routes, and endpoint teardown.
package tcp

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// Deliver one actual queued ACK to the real endpoint processing path. The
// small, single suffix is exactly below RFC6675's byte/block loss thresholds.
func privateRACKSuffixACK(t *testing.T, c *ptoTestContext, ack seqnum.Value, suffix header.SACKBlock) {
	t.Helper()
	seg := newOutgoingSegment(c.ep.ID, c.clock, buffer.Buffer{}, 0)
	defer seg.DecRef()
	seg.sequenceNumber = c.ep.rcv.RcvNxt
	seg.ackNumber, seg.window = ack, c.ep.snd.SndWnd
	seg.flags = header.TCPFlagAck
	seg.parsedOptions.SACKBlocks = []header.SACKBlock{suffix}
	if !c.ep.segmentQueue.enqueue(seg) {
		t.Fatal("real endpoint rejected suffix ACK enqueue")
	}
	if err := c.ep.handleSegmentsLocked(); err != nil {
		t.Fatalf("real suffix ACK processing: %s", err)
	}
}

// Caller owns ep.mu. A grown sixteen-packet flight models the observed body
// burst, rather than changing a live network's congestion-control policy.
func privateRACKSuffixFlight(t *testing.T, c *ptoTestContext) (seqnum.Value, [][]byte, header.SACKBlock) {
	t.Helper()
	s := c.ep.snd
	if s.MaxPayloadSize != ptoTestPayloadSize || !c.ep.SACKPermitted || c.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 {
		t.Fatal("real fixture is not SMSS1000 with SACK/RACK")
	}
	s.SndCwnd = 16
	first := s.SndNxt
	data := make([][]byte, 14)
	for index := range data {
		data[index] = bytes.Repeat([]byte{byte(index + 1)}, ptoTestPayloadSize)
		c.write(data[index])
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	suffix := header.SACKBlock{Start: s.SndNxt, End: s.SndNxt.Add(258)}
	suffixData := bytes.Repeat([]byte{0xee}, 258)
	c.write(suffixData)
	c.expectPacket(t, suffix.Start, suffixData)
	c.expectNoPacket(t)
	c.advance(100 * time.Millisecond)
	privateRACKSuffixACK(t, c, first, suffix)
	c.expectNoPacket(t)
	if s.SndUna != first || c.ep.scoreboard.Sacked() != 258 || c.ep.scoreboard.IsRangeLost(header.SACKBlock{Start: first, End: first.Add(ptoTestPayloadSize)}) {
		t.Fatal("single small suffix did not preserve the fourteen-hole RFC6675 premise")
	}
	if s.FastRecovery.Active || !s.reorderTimer.enabled() {
		t.Fatal("RACK did not defer loss to its genuine reorder deadline")
	}
	return first, data, suffix
}

// A real suffix SACK marks fourteen old segments lost via the production
// reorder timer. Available cwnd must repair a burst immediately, not keep
// counting those declared-lost originals until another RTO/partial ACK.
func TestPrivateRACKSuffixSACKRepairsBurstWithoutRTO(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	first, data, suffix := privateRACKSuffixFlight(t, c)
	s := c.ep.snd
	deadline := s.reorderTimer.target
	c.advance(deadline.Sub(c.clock.NowMonotonic()))
	if !s.FastRecovery.Active || s.state != tcpip.SACKRecovery || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 {
		t.Fatalf("genuine RACK recovery missing: active=%t state=%v timeouts=%d", s.FastRecovery.Active, s.state, c.ep.stack.Stats().TCP.Timeouts.Value())
	}
	markedOrSent := 0
	for seg := s.writeList.Front(); seg != nil && seg.sequenceNumber.LessThan(suffix.Start); seg = seg.Next() {
		if seg.lost || seg.xmitCount > 1 {
			markedOrSent++
		}
	}
	if markedOrSent != len(data) {
		t.Fatalf("production RACK did not identify the complete hole: marked-or-retransmitted=%d", markedOrSent)
	}
	want := min(len(data), int(s.SndCwnd))
	if want <= 1 {
		t.Fatal("setup did not leave a genuine multi-packet recovery window")
	}
	t.Logf("RACK suffix258 hole14: cwnd=%d pipe=%d ssthresh=%d marked-or-sent=%d", s.SndCwnd, s.Outstanding, s.Ssthresh, markedOrSent)
	for index := range want {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	s.SetPipe()
	if s.Outstanding != want {
		t.Fatalf("retransmitted physical flight counted other than once: pipe=%d want=%d", s.Outstanding, want)
	}
	// The next real advancing ACK frees exactly that flight; remaining losses
	// may be repaired without waiting for the fallback retransmit timer.
	c.advance(100 * time.Millisecond)
	privateRACKSuffixACK(t, c, first.Add(seqnum.Size(want*ptoTestPayloadSize)), suffix)
	for index := want; index < len(data); index++ {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	c.advance(100 * time.Millisecond)
	c.receive(t, suffix.End, s.SndWnd, nil)
	c.expectNoPacket(t)
	if s.SndUna != suffix.End || s.Outstanding != 0 || s.writeList.Front() != nil || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 {
		t.Fatalf("real cumulative ACK did not drain repair ownership without RTO: una=%d pipe=%d timeouts=%d", s.SndUna, s.Outstanding, c.ep.stack.Stats().TCP.Timeouts.Value())
	}
}

// Observed SACK is not itself permission to discard in-flight originals. The
// exact production reorder timer must still protect not-yet-lost data.
func TestPrivateRACKSuffixSACKKeepsReorderingFlight(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	_, data, _ := privateRACKSuffixFlight(t, c)
	s := c.ep.snd
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()) - time.Nanosecond)
	c.expectNoPacket(t)
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg.lost || seg.xmitCount != 1 {
			t.Fatal("not-yet-lost flight was marked or retransmitted before reorder deadline")
		}
	}
	// Before recovery SetPipe deliberately leaves the original outstanding
	// count intact; even the small SACKed suffix has not been subtracted yet.
	if s.Outstanding != len(data)+1 {
		t.Fatalf("pre-recovery original flight changed: outstanding=%d want=%d", s.Outstanding, len(data)+1)
	}
}

// Exercise physical-flight counting on the real sender's retained data, both
// before and after a retransmission. HighRxt must not double-count a RACK
// retransmission whose actual send clears lost. A repeated loss must remove
// that transmission again, not exempt all xmitCount>1 data from loss detection.
func TestPrivateRACKPipeCountsRetransmittedFlightOnce(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	data := bytes.Repeat([]byte{0xab}, ptoTestPayloadSize)
	first := s.SndNxt
	c.write(data)
	c.expectPacket(t, first, data)
	s.enterRecovery()
	seg := s.writeList.Front()
	seg.lost = true
	s.SetPipe()
	if s.Outstanding != 0 {
		t.Fatalf("RACK-marked original remains in pipe: %d", s.Outstanding)
	}
	s.resendSegment()
	c.expectPacket(t, first, data)
	if seg.lost || seg.xmitCount != 2 {
		t.Fatal("actual retransmission did not clear lost and advance xmitCount")
	}
	s.SetPipe()
	if s.Outstanding != 1 {
		t.Fatalf("actual retransmission counted other than once: %d", s.Outstanding)
	}
	seg.lost = true
	s.SetPipe()
	if s.Outstanding != 0 {
		t.Fatalf("second loss of a retransmission remains in pipe: %d", s.Outstanding)
	}
}

// Reorder-timer loss can arrive while recovery is already active. No ACK
// or initial forced resend then recomputes the old pipe count on its behalf.
func TestPrivateRACKActiveRecoveryRecomputesNewLossPipe(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	first, data, _ := privateRACKSuffixFlight(t, c)
	s := c.ep.snd
	// The real suffix ACK first establishes the unmodified reorder deadline.
	// Enter the real recovery state only afterward: its pending timer must
	// now dispatch new losses without another ACK or initial forced resend.
	s.cc.HandleLossDetected()
	s.enterRecovery()
	if s.Outstanding < s.SndCwnd {
		t.Fatal("active-recovery setup does not exercise a blocked stale pipe")
	}
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()))
	if !s.FastRecovery.Active || c.ep.stack.Stats().TCP.FastRetransmit.Value() != 0 || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 {
		t.Fatal("already-active timer path escaped through initial forced resend or RTO")
	}
	want := min(len(data), int(s.SndCwnd))
	for index := range want {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	s.SetPipe()
	if s.Outstanding != want {
		t.Fatalf("active-recovery burst physical flight=%d want=%d", s.Outstanding, want)
	}
}

// A retained multi-SMSS (GSO-shaped) write entry is split by the real
// retransmit path. This accounting control constructs the prior transmission
// state explicitly; the composed root above separately proves actual route
// transmission and RACK loss marking without synthetic lost flags.
func TestPrivateRACKPipePreservesLostGSORemainder(t *testing.T) {
	for _, lost := range []bool{false, true} {
		privateRACKPipeGSORemainder(t, lost)
	}
}

func privateRACKPipeGSORemainder(t *testing.T, lost bool) {
	t.Helper()
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	first := s.SndNxt
	seg := privateRACKRetainedGSO(c, lost)
	s.cc.HandleLossDetected()
	s.enterRecovery()
	c.ep.scoreboard.Insert(header.SACKBlock{Start: first.Add(2 * ptoTestPayloadSize), End: s.SndNxt})
	s.SetPipe()
	want := 2
	if lost {
		want = 0
	}
	if s.Outstanding != want {
		t.Fatalf("multi-SMSS pipe with lost=%t is%d want%d", lost, s.Outstanding, want)
	}
	s.resendSegment()
	c.expectPacket(t, first, bytes.Repeat([]byte{0xab}, ptoTestPayloadSize))
	remainder := seg.Next()
	if remainder == nil || remainder.payloadSize() != ptoTestPayloadSize+500 || remainder.lost != lost || remainder.xmitCount != 1 {
		t.Fatal("unsent split remainder lost its original transmission/loss state")
	}
	if seg.lost || seg.xmitCount != 2 {
		t.Fatal("actual first-part retransmission did not clear only its own loss")
	}
	s.SetPipe()
	want = 2
	if lost {
		want = 1
	}
	if s.Outstanding != want {
		t.Fatalf("post-split retransmitted pipe with lost=%t is%d want%d", lost, s.Outstanding, want)
	}
	if lost {
		// Lose that actual retransmission again. No later ACK is allowed
		// to rescue a stale count before DoRecovery's own dispatch.
		seg.lost = true
		s.SndCwnd = 1
		s.rc.DoRecovery(nil, false)
		c.expectPacket(t, first, bytes.Repeat([]byte{0xab}, ptoTestPayloadSize))
		c.expectNoPacket(t)
		s.SetPipe()
		if seg.lost || seg.xmitCount != 3 || !remainder.lost || s.Outstanding != 1 {
			t.Fatal("re-lost retransmission bypassed recovery or hid unsent GSO loss")
		}
	}
}

// Caller owns ep.mu. The actual endpoint owns this retained original physical
// transmission model, including its send-buffer accounting and packet refs.
func privateRACKRetainedGSO(c *ptoTestContext, lost bool) *segment {
	s := c.ep.snd
	const payload = 2*ptoTestPayloadSize + 500
	seg := newOutgoingSegment(c.ep.ID, c.clock, buffer.MakeWithData(bytes.Repeat([]byte{0xab}, payload)), 0)
	seg.setOwner(c.ep, sendQ)
	seg.sequenceNumber, seg.flags = s.SndNxt, header.TCPFlagAck
	seg.xmitCount, seg.xmitTime, seg.lost = 1, c.clock.NowMonotonic(), lost
	c.ep.sndQueueInfo.sndQueueMu.Lock()
	c.ep.sndQueueInfo.SndBufUsed += payload
	c.ep.sndQueueInfo.sndQueueMu.Unlock()
	s.writeList.PushBack(seg)
	s.SndNxt = s.SndNxt.Add(payload)
	s.Outstanding = 3
	return seg
}

// Independent OLD RED for the split itself: no pipe calculation or actual
// retransmission may mask the retained remainder losing its original state.
func TestPrivateRACKSplitPreservesOriginalLossState(t *testing.T) {
	for _, lost := range []bool{false, true} {
		privateRACKSplitOriginalLoss(t, lost)
	}
}

func privateRACKSplitOriginalLoss(t *testing.T, lost bool) {
	t.Helper()
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	seg := privateRACKRetainedGSO(c, lost)
	first, xmitTime := seg.sequenceNumber, seg.xmitTime
	s.splitSeg(seg, ptoTestPayloadSize)
	remainder := seg.Next()
	if remainder == nil || seg.lost != lost || remainder.lost != lost {
		t.Fatalf("split changed original physical loss: want%t first%t remainder=%v", lost, seg.lost, remainder)
	}
	if seg.sequenceNumber != first || remainder.sequenceNumber != first.Add(ptoTestPayloadSize) ||
		seg.payloadSize() != ptoTestPayloadSize || remainder.payloadSize() != ptoTestPayloadSize+500 ||
		seg.xmitCount != 1 || remainder.xmitCount != 1 || seg.xmitTime != xmitTime || remainder.xmitTime != xmitTime {
		t.Fatal("split changed sequence range, payload length, or prior transmission identity")
	}
	entries := 0
	for entry := s.writeList.Front(); entry != nil; entry = entry.Next() {
		entries++
	}
	if seg.ep != c.ep || remainder.ep != c.ep || seg.qFlags != sendQ || remainder.qFlags != sendQ ||
		entries != 2 || s.writeList.Front() != seg || s.writeList.Back() != remainder {
		t.Fatal("split did not preserve both endpoint-owned write entries")
	}
	c.ep.sndQueueInfo.sndQueueMu.Lock()
	used := c.ep.sndQueueInfo.SndBufUsed
	c.ep.sndQueueInfo.sndQueueMu.Unlock()
	if used != 2*ptoTestPayloadSize+500 {
		t.Fatal("split duplicated or released send-buffer ownership")
	}
	c.expectNoPacket(t)
}

// The RFC6675 path intentionally keeps its separate HighRxt accounting.
// RACK's time-based optimization must not change the non-RACK algorithm.
func TestPrivateRACKPipeLeavesRFC6675AccountingUnchanged(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	c.ep.tcpRecovery = 0
	first := s.SndNxt
	data := bytes.Repeat([]byte{0xcd}, ptoTestPayloadSize)
	for index := range 3 {
		c.write(data)
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data)
	}
	s.cc.HandleLossDetected()
	s.enterRecovery()
	c.ep.scoreboard.Insert(header.SACKBlock{Start: first.Add(ptoTestPayloadSize), End: s.SndNxt})
	if !c.ep.scoreboard.IsRangeLost(header.SACKBlock{Start: first, End: first.Add(ptoTestPayloadSize)}) {
		t.Fatal("RFC6675 two-SMSS suffix did not meet its loss threshold")
	}
	s.SetPipe()
	if s.Outstanding != 1 {
		t.Fatalf("RFC6675 lost original/HighRxt pipe=%d want1", s.Outstanding)
	}
	s.resendSegment()
	c.expectPacket(t, first, data)
	s.SetPipe()
	if s.Outstanding != 1 {
		t.Fatalf("RFC6675 retransmitted flight changed: pipe=%d want1", s.Outstanding)
	}
}
