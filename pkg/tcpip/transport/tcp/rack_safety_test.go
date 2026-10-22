// Private RACK recovery safety controls. These are additive to the frozen V2
// pipe tests and do not change any production source, timer, or policy.
package tcp

import (
	"bytes"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

type privateRACKSafetyLossResponse struct {
	at                          tcpip.MonotonicTime
	pipe, cwnd, thresholdBefore int
	thresholdAfter              int
}

// All accesses use the actual endpoint mutex, including timer callbacks.
// The embedded delegate keeps the real Reno/CUBIC behavior for every method.
type privateRACKSafetyCC struct {
	congestionControl
	snd       *sender
	lossCalls int
	rtoCalls  int
	responses [4]privateRACKSafetyLossResponse
}

// +checklocks:c.snd.ep.mu
func (c *privateRACKSafetyCC) HandleLossDetected() {
	response := privateRACKSafetyLossResponse{
		at:              c.snd.ep.stack.Clock().NowMonotonic(),
		pipe:            c.snd.Outstanding,
		cwnd:            c.snd.SndCwnd,
		thresholdBefore: c.snd.Ssthresh,
	}
	c.congestionControl.HandleLossDetected()
	response.thresholdAfter = c.snd.Ssthresh
	if c.lossCalls < len(c.responses) {
		c.responses[c.lossCalls] = response
	}
	c.lossCalls++
}

// +checklocks:c.snd.ep.mu
func (c *privateRACKSafetyCC) HandleRTOExpired() {
	c.rtoCalls++
	c.congestionControl.HandleRTOExpired()
}

// A classic third fresh duplicate ACK can force the first replay while the
// RACK time criterion still protects the original. Record the two supported
// accounting models without declaring RFC6675's two-copy rule mandatory for
// its RACK replacement. The assertions pin the real transition and its bound.
func TestPrivateRACKForcedFirstWithClockAllowanceRecordsFlight(t *testing.T) {
	const resolution = 500 * time.Microsecond
	c := privateRACKSafetyContextWithResolution(t, resolution)
	// Socket-option callbacks acquire ep.mu, so configure before taking it.
	c.ep.ops.SetDelayOption(false)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	if _, ok := s.cc.(*renoState); !ok {
		t.Fatal("forced-first accounting control requires the existing real Reno fixture")
	}
	if s.SndCwnd != 10 || s.MaxPayloadSize != ptoTestPayloadSize || c.ep.stack.ClockResolution() != resolution || c.ep.ops.GetDelayOption() {
		t.Fatal("forced-first fixture did not preserve cwnd10/SMSS1000/TCP_NODELAY with the requested clock resolution")
	}
	cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
	s.cc = cc
	// A freshly initialized sender has Last=ISS and Una=ISS+1. Its
	// duplicate-ACK recovery guard intentionally rejects Una-1 == Last.
	// Advance that guard with actual route data and a cumulative ACK,
	// not a direct edit of Last, Una, DupAckCount, or the real CC policy.
	warmStart := s.SndNxt
	warmData := bytes.Repeat([]byte{0x90}, ptoTestPayloadSize)
	c.write(warmData)
	c.expectPacket(t, warmStart, warmData)
	c.expectNoPacket(t)
	c.advance(100 * time.Millisecond)
	warmEnd := warmStart.Add(ptoTestPayloadSize)
	c.receive(t, warmEnd, s.SndWnd, nil)
	c.expectNoPacket(t)
	c.ep.sndQueueInfo.sndQueueMu.Lock()
	warmSendBytes := c.ep.sndQueueInfo.SndBufUsed
	c.ep.sndQueueInfo.sndQueueMu.Unlock()
	if s.SndUna != warmEnd || s.SndNxt != warmEnd || s.Outstanding != 0 || s.writeList.Front() != nil || s.writeNext != nil || warmSendBytes != 0 || s.FastRecovery.Active || !s.FastRecovery.Last.LessThan(s.SndUna-1) || s.DupAckCount != 0 || cc.lossCalls != 0 || cc.rtoCalls != 0 || s.SndCwnd != 11 {
		t.Fatalf("actual warm-up ACK did not establish empty ownership and an eligible recovery guard: una=%d nxt=%d pipe=%d list_empty=%t next_nil=%t owned_send_bytes=%d active=%t last=%d ack_minus_one=%d dupacks=%d losses=%d RTOs=%d cwnd=%d", s.SndUna, s.SndNxt, s.Outstanding, s.writeList.Front() == nil, s.writeNext == nil, warmSendBytes, s.FastRecovery.Active, s.FastRecovery.Last, s.SndUna-1, s.DupAckCount, cc.lossCalls, cc.rtoCalls, s.SndCwnd)
	}
	t.Logf("RACK_FORCED_FIRST_WARMUP: actual_cumulative_ack=%d recovery_last=%d guard_last_lt_ack_minus_one=%t retained_owners=0 pipe=0 naturally_grown_reno_cwnd=%d", s.SndUna, s.FastRecovery.Last, s.FastRecovery.Last.LessThan(s.SndUna-1), s.SndCwnd)
	first := s.SndNxt
	originalXmit := c.clock.NowMonotonic()
	full := bytes.Repeat([]byte{0xa1}, ptoTestPayloadSize)
	for index := range 7 {
		c.write(full)
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), full)
	}
	suffixStart := s.SndNxt
	short := bytes.Repeat([]byte{0xb2}, 100)
	for index := range 3 {
		c.write(short)
		c.expectPacket(t, suffixStart.Add(seqnum.Size(index*len(short))), short)
	}
	c.expectNoPacket(t)
	if s.Outstanding != 10 || s.SndCwnd != 11 {
		t.Fatalf("ten actual original route writes did not establish the app-limited flight: pipe=%d naturally_grown_cwnd=%d", s.Outstanding, s.SndCwnd)
	}
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg.xmitCount != 1 || seg.xmitTime != originalXmit || seg.lost {
			t.Fatal("original physical flight did not share a clean transmission quantum")
		}
	}
	c.advance(100 * time.Millisecond)
	for index := range 3 {
		guardLast := s.FastRecovery.Last
		guardEligible := guardLast.LessThan(s.SndUna - 1)
		dupBefore := s.DupAckCount
		if !guardEligible || s.FastRecovery.Active || dupBefore != index {
			t.Fatalf("fresh SACK%d lacked the expected real recovery guard: last=%d ack_minus_one=%d eligible=%t active=%t dupacks_before=%d", index+1, guardLast, s.SndUna-1, guardEligible, s.FastRecovery.Active, dupBefore)
		}
		privateRACKSuffixACK(t, c, first, header.SACKBlock{
			Start: suffixStart,
			End:   suffixStart.Add(seqnum.Size((index + 1) * len(short))),
		})
		t.Logf("RACK_FORCED_FIRST_ACK: ordinal=%d cumulative_ack=%d fresh_sacked_bytes=%d guard_last_before=%d guard_eligible_before=%t dupacks_before=%d dupacks_after=%d active_after=%t responses=%d recovery_last_after=%d", index+1, s.SndUna, c.ep.scoreboard.Sacked(), guardLast, guardEligible, dupBefore, s.DupAckCount, s.FastRecovery.Active, cc.lossCalls, s.FastRecovery.Last)
		if s.SndUna != first || c.ep.scoreboard.Sacked() != seqnum.Size((index+1)*len(short)) {
			t.Fatal("synthetic queued SACK did not add its exact fresh suffix without cumulative progress")
		}
		if index < 2 {
			c.expectNoPacket(t)
			if s.FastRecovery.Active || cc.lossCalls != 0 || s.DupAckCount != index+1 {
				t.Fatal("clock allowance did not preserve the first two duplicate-ACK boundaries")
			}
		} else if !s.FastRecovery.Active || cc.lossCalls != 1 || s.DupAckCount != 0 {
			t.Fatalf("third fresh queued SACK did not enter classic recovery before route inspection: active=%t responses=%d dupacks=%d last=%d una=%d", s.FastRecovery.Active, cc.lossCalls, s.DupAckCount, s.FastRecovery.Last, s.SndUna)
		}
	}
	c.expectPacket(t, first, full)
	c.expectNoPacket(t)
	head := s.writeList.Front()
	if !s.FastRecovery.Active || s.state != tcpip.SACKRecovery || s.SndUna != first || s.rc.Reord || s.rc.ReoWnd != 0 || cc.lossCalls != 1 || cc.rtoCalls != 0 || s.Ssthresh != 5 || s.SndCwnd != 8 {
		t.Fatalf("third actual fresh duplicate ACK did not take the intended classic recovery path: active=%t state=%v una=%d reord=%t reo=%s losses=%d RTOs=%d ssthresh=%d cwnd=%d", s.FastRecovery.Active, s.state, s.SndUna, s.rc.Reord, s.rc.ReoWnd, cc.lossCalls, cc.rtoCalls, s.Ssthresh, s.SndCwnd)
	}
	if head == nil || head.xmitCount != 2 || head.lost || c.ep.stack.Stats().TCP.FastRetransmit.Value() != 1 || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 {
		t.Fatal("actual forced head replay was absent or escaped through a timer/repeated replay")
	}
	if c.ep.scoreboard.Sacked() != 300 || c.ep.scoreboard.IsRangeLost(header.SACKBlock{Start: first, End: first.Add(ptoTestPayloadSize)}) {
		t.Fatal("three adjacent short SACKs crossed the RFC6675 range/byte loss threshold")
	}
	remaining := originalXmit.Sub(c.clock.NowMonotonic()) + s.rc.RTT + s.rc.ReoWnd + c.ep.stack.ClockResolution()
	if remaining != resolution {
		t.Fatalf("head's pre-replay RACK criterion was not protected by positive clock allowance: remaining=%s want=%s", remaining, resolution)
	}
	latestCopies := 0
	for seg := s.writeList.Front(); seg != nil && seg.sequenceNumber.LessThan(suffixStart); seg = seg.Next() {
		if seg.lost || (seg != head && (seg.xmitCount != 1 || seg.xmitTime != originalXmit)) {
			t.Fatal("a non-replayed original was marked lost despite the common protected RACK criterion")
		}
		latestCopies++
	}
	if latestCopies != 7 {
		t.Fatalf("unexpected unsacked latest-transmission count: %d", latestCopies)
	}
	pipeBeforeNew := s.Outstanding
	if pipeBeforeNew != latestCopies && pipeBeforeNew != latestCopies+1 {
		t.Fatalf("forced-first accounting escaped both bounded models: pipe=%d latest=%d", pipeBeforeNew, latestCopies)
	}
	// Pin the actual admission consequence of the recorded estimate, not a
	// normative choice between implicitly lost original and two-copy belief.
	newSequence := s.SndNxt
	newData := bytes.Repeat([]byte{0xc3}, ptoTestPayloadSize)
	c.write(newData)
	admitted := pipeBeforeNew < s.SndCwnd
	if admitted {
		c.expectPacket(t, newSequence, newData)
	} else {
		if s.SndNxt != newSequence {
			t.Fatal("new sequence advanced despite a full accounting window")
		}
	}
	c.expectNoPacket(t)
	if s.Outstanding != s.SndCwnd || s.SndCwnd != 8 || cc.lossCalls != 1 || cc.rtoCalls != 0 {
		t.Fatal("new write did not respect the recorded congestion-window estimate")
	}
	t.Logf("RACK_FORCED_FIRST_ACCOUNTING: protected_remaining=%s latest_unsacked=%d possible_unsacked_original_and_replay_copies=%d pipe_before_new=%d cwnd=%d new_MSS_admitted=%t implicit_original_loss_belief_not_resolved_by_this_control", remaining, latestCopies, latestCopies+1, pipeBeforeNew, s.SndCwnd, admitted)
}

// Actual RACK feedback must cause a second congestion response when a replay
// from the next transmission window is itself lost. No test assigns lost,
// enters recovery, or calls a CC method. The recorder delegates real policy.
func TestPrivateRACKLostRetransmissionRequiresNewCongestionResponse(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	if _, ok := s.cc.(*renoState); !ok {
		t.Fatal("retransmission-loss response control requires the existing real Reno fixture")
	}
	cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
	s.cc = cc
	first, data, _ := privateRACKSuffixFlight(t, c)
	if cc.lossCalls != 0 {
		t.Fatal("initial suffix ACK prematurely invoked congestion response")
	}
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()))
	initialRepairs := min(len(data), s.SndCwnd)
	if initialRepairs < 3 || cc.lossCalls != 1 || cc.rtoCalls != 0 || !s.FastRecovery.Active {
		t.Fatalf("initial actual RACK loss did not produce a usable genuine recovery window: repairs=%d losses=%d RTOs=%d active=%t", initialRepairs, cc.lossCalls, cc.rtoCalls, s.FastRecovery.Active)
	}
	for index := range initialRepairs {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	head := s.writeList.Front()
	if head == nil {
		t.Fatal("initial genuine repair did not retain its original send owner")
	}
	firstReplayTime := head.xmitTime
	firstThreshold := s.Ssthresh
	firstRecoveryCwnd := s.SndCwnd
	firstRecoveryLast := s.FastRecovery.Last
	if head.xmitCount != 2 || head.lost || firstThreshold <= 2 {
		t.Fatal("initial actual replay or real threshold headroom was not established")
	}
	var beforeXmit [14]uint32
	for index, seg := 0, s.writeList.Front(); index < len(data); index, seg = index+1, seg.Next() {
		if seg == nil {
			t.Fatal("retained original data vanished before retransmission-loss feedback")
		}
		beforeXmit[index] = seg.xmitCount
		if index < initialRepairs && (seg.xmitCount != 2 || seg.xmitTime != firstReplayTime || seg.lost) {
			t.Fatal("initial actual repair burst did not share its real replay generation")
		}
	}
	c.advance(100 * time.Millisecond)
	c.expectNoPacket(t)
	feedback := header.SACKBlock{
		Start: first.Add(seqnum.Size((initialRepairs - 1) * ptoTestPayloadSize)),
		End:   first.Add(seqnum.Size(initialRepairs * ptoTestPayloadSize)),
	}
	privateRACKSuffixACK(t, c, first, feedback)
	head = s.writeList.Front()
	if head == nil {
		t.Fatal("nonadvancing SACK unexpectedly retired the missing head owner")
	}
	if !s.FastRecovery.Active || s.state != tcpip.SACKRecovery || s.FastRecovery.Last != firstRecoveryLast || s.SndUna != first || s.rc.XmitTime != firstReplayTime || s.rc.EndSequence != feedback.End || head.xmitCount != 3 || c.ep.stack.Stats().TCP.FastRetransmit.Value() != 1 || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 || cc.rtoCalls != 0 {
		t.Fatalf("new real SACK did not establish actual RACK re-loss/replay while already active: active=%t una=%d rack_latest=%s want=%s end=%d want_end=%d head_xmits=%d forced_replays=%d timeouts=%d observed_RTOs=%d", s.FastRecovery.Active, s.SndUna, s.rc.XmitTime, firstReplayTime, s.rc.EndSequence, feedback.End, head.xmitCount, c.ep.stack.Stats().TCP.FastRetransmit.Value(), c.ep.stack.Stats().TCP.Timeouts.Value(), cc.rtoCalls)
	}
	actualRepairs := 0
	for index, seg := 0, s.writeList.Front(); index < len(data); index, seg = index+1, seg.Next() {
		if seg == nil {
			t.Fatal("retained data vanished after a nonadvancing SACK")
		}
		if seg.xmitCount == beforeXmit[index] {
			continue
		}
		if seg.xmitCount != beforeXmit[index]+1 {
			t.Fatal("one queued ACK produced repeated transmission of the same retained range")
		}
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
		actualRepairs++
	}
	c.expectNoPacket(t)
	if actualRepairs == 0 {
		t.Fatal("new actual RACK loss did not dispatch a real repair")
	}
	// Every older unsacked latest copy is now genuinely RACK-marked lost;
	// the newly written repair burst is the entire remaining pipe. A real
	// congestion response must limit actual dispatch, not merely statistics.
	if s.Outstanding != actualRepairs || actualRepairs > s.SndCwnd {
		t.Fatalf("actual re-loss repair burst escaped the resulting flight allowance: repairs=%d pipe=%d cwnd=%d", actualRepairs, s.Outstanding, s.SndCwnd)
	}
	if cc.lossCalls == 1 {
		t.Fatalf("RACK_RETRANSMISSION_LOSS_WITHOUT_SECOND_CC_RESPONSE: actual_repairs=%d original_replay_at=%s second_replay_at=%s loss_responses=%d ssthresh_before=%d ssthresh_after=%d cwnd_before=%d cwnd_after=%d active=%t timeout_count=0; all lost decisions came from real ACK/timer processing", actualRepairs, firstReplayTime, head.xmitTime, cc.lossCalls, firstThreshold, s.Ssthresh, firstRecoveryCwnd, s.SndCwnd, s.FastRecovery.Active)
	}
	if cc.lossCalls != 2 || cc.responses[1].thresholdBefore != firstThreshold || cc.responses[1].thresholdAfter >= firstThreshold || s.Ssthresh != cc.responses[1].thresholdAfter {
		t.Fatalf("real retransmission loss did not invoke exactly one effective additional CC response: responses=%d first_threshold=%d second=%+v current_threshold=%d", cc.lossCalls, firstThreshold, cc.responses[1], s.Ssthresh)
	}
	if s.SndCwnd <= 0 || s.SndCwnd >= firstRecoveryCwnd || actualRepairs >= firstRecoveryCwnd {
		t.Fatalf("RACK_RETRANSMISSION_LOSS_RESPONSE_DID_NOT_REDUCE_WINDOW: old_cwnd=%d resulting_cwnd=%d actual_repairs=%d pipe=%d; a threshold/callback-only change is not an effective response", firstRecoveryCwnd, s.SndCwnd, actualRepairs, s.Outstanding)
	}
	responseCwnd := s.SndCwnd
	// Repeating the same ACK at the same ingress time supplies no new loss
	// window. Previously marked originals must not each trigger another CC
	// response, and the just-written replay cannot already have expired.
	privateRACKSuffixACK(t, c, first, feedback)
	c.expectNoPacket(t)
	if cc.lossCalls != 2 || cc.rtoCalls != 0 || s.Ssthresh != cc.responses[1].thresholdAfter || s.SndCwnd != responseCwnd {
		t.Fatalf("one retransmission-loss window caused repeated congestion responses or a new window: loss_responses=%d RTOs=%d threshold=%d second_threshold=%d cwnd=%d response_cwnd=%d", cc.lossCalls, cc.rtoCalls, s.Ssthresh, cc.responses[1].thresholdAfter, s.SndCwnd, responseCwnd)
	}
	t.Logf("RACK_RETRANSMISSION_LOSS_CC: responses=%d first=%+v second=%+v old_cwnd=%d resulting_cwnd=%d actual_second_repairs=%d same_ingress_duplicate_did_not_repeat_response", cc.lossCalls, cc.responses[0], cc.responses[1], firstRecoveryCwnd, responseCwnd, actualRepairs)
}
