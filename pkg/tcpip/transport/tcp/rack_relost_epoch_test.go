// Private adjacent controls for the exact RACK loss epoch candidate.
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

// Caller owns ep.mu. All initial loss marks and replays come from the
// existing suffix ACK and the real reorder timer, not a test-set lost flag.
func privateRACKEpochStart(t *testing.T, c *ptoTestContext, policy tcpip.CongestionControlOption) (*privateRACKSafetyCC, seqnum.Value, [][]byte, int) {
	t.Helper()
	s := c.ep.snd
	s.cc = s.initCongestionControl(policy)
	cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
	s.cc = cc
	first, data, _ := privateRACKSuffixFlight(t, c)
	c.advance(s.reorderTimer.target.Sub(c.clock.NowMonotonic()))
	repairs := min(len(data), s.SndCwnd)
	for index := range repairs {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	if cc.lossCalls != 1 || cc.rtoCalls != 0 || s.rc.lossEpoch != 1 || !s.FastRecovery.Active || repairs < 3 {
		t.Fatalf("initial real RACK recovery missing: responses=%d RTOs=%d epoch=%d active=%t repairs=%d", cc.lossCalls, cc.rtoCalls, s.rc.lossEpoch, s.FastRecovery.Active, repairs)
	}
	for index, seg := 0, s.writeList.Front(); index < repairs; index, seg = index+1, seg.Next() {
		if seg == nil || seg.xmitCount != 2 || seg.lost || seg.lossEpoch != s.rc.lossEpoch {
			t.Fatal("actual initial repair was not stamped with its new loss epoch")
		}
	}
	return cc, first, data, repairs
}

// Caller owns ep.mu. Snapshot retained transmit counts before the queued ACK;
// consume every actual route write caused by that ACK in exact list order.
func privateRACKEpochACK(t *testing.T, c *ptoTestContext, first seqnum.Value, data [][]byte, index int) int {
	t.Helper()
	if len(data) != 14 || index < 0 || index >= len(data) {
		t.Fatal("epoch ACK helper requires the existing fourteen-packet body")
	}
	var before [14]uint32
	for pos, seg := 0, c.ep.snd.writeList.Front(); pos < len(data); pos, seg = pos+1, seg.Next() {
		if seg == nil {
			t.Fatal("retained body vanished before a nonadvancing ACK")
		}
		before[pos] = seg.xmitCount
	}
	privateRACKSuffixACK(t, c, first, header.SACKBlock{
		Start: first.Add(seqnum.Size(index * ptoTestPayloadSize)),
		End:   first.Add(seqnum.Size((index + 1) * ptoTestPayloadSize)),
	})
	writes := 0
	for pos, seg := 0, c.ep.snd.writeList.Front(); pos < len(data); pos, seg = pos+1, seg.Next() {
		if seg == nil {
			t.Fatal("nonadvancing ACK retired a retained body owner")
		}
		if seg.xmitCount == before[pos] {
			continue
		}
		if seg.xmitCount != before[pos]+1 {
			t.Fatal("one ACK repeated the same body transmission")
		}
		c.expectPacket(t, first.Add(seqnum.Size(pos*ptoTestPayloadSize)), data[pos])
		writes++
	}
	c.expectNoPacket(t)
	if c.ep.snd.SndUna != first || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 || c.ep.stack.Stats().TCP.FastRetransmit.Value() != 1 {
		t.Fatal("epoch ACK escaped through cumulative completion, RTO, or another forced replay")
	}
	return writes
}

func TestPrivateRACKEpochReLossUsesRealRenoAndCubic(t *testing.T) {
	for _, policy := range []tcpip.CongestionControlOption{ccReno, ccCubic} {
		func() {
			t.Logf("real_CC_case=%s", policy)
			c := newPTOTestContext(t)
			c.ep.mu.Lock()
			defer c.ep.mu.Unlock()
			cc, first, data, repairs := privateRACKEpochStart(t, c, policy)
			s := c.ep.snd
			bounds := s.FastRecovery
			oldCwnd, oldThreshold := s.SndCwnd, s.Ssthresh
			c.advance(100 * time.Millisecond)
			c.expectNoPacket(t)
			writes := privateRACKEpochACK(t, c, first, data, repairs-1)
			if cc.lossCalls != 2 || cc.rtoCalls != 0 || s.rc.lossEpoch != 2 || s.SndCwnd >= oldCwnd || s.Ssthresh >= oldThreshold || s.SndCwnd > s.Ssthresh || writes == 0 || writes > s.SndCwnd || s.Outstanding != writes {
				t.Fatalf("real %s response did not reduce actual replay flight: responses=%d epoch=%d cwnd=%d->%d threshold=%d->%d writes=%d pipe=%d", policy, cc.lossCalls, s.rc.lossEpoch, oldCwnd, s.SndCwnd, oldThreshold, s.Ssthresh, writes, s.Outstanding)
			}
			if !s.FastRecovery.Active || s.FastRecovery.First != bounds.First || s.FastRecovery.Last != bounds.Last || s.FastRecovery.HighRxt != bounds.HighRxt || s.FastRecovery.RescueRxt != bounds.RescueRxt || s.FastRecovery.MaxCwnd > s.SndCwnd {
				t.Fatal("active response restarted or relaxed the existing recovery bounds")
			}
			reduced := s.SndCwnd
			for range 2 {
				if n := privateRACKEpochACK(t, c, first, data, repairs-1); n != 0 || cc.lossCalls != 2 || s.rc.lossEpoch != 2 || s.SndCwnd != reduced {
					t.Fatal("repeated same-window ACK cut or dispatched again")
				}
			}
			t.Logf("real_CC=%s first_cwnd=%d reduced_cwnd=%d second_actual_repairs=%d responses=%d", policy, oldCwnd, reduced, writes, cc.lossCalls)
		}()
	}
}

func TestPrivateRACKEpochLateOldLossAndLaterNewLoss(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	cc, first, data, repairs := privateRACKEpochStart(t, c, ccReno)
	s := c.ep.snd
	if repairs != 10 {
		t.Fatal("late-old-window control requires the real Reno ten-packet repair flight")
	}
	c.advance(100 * time.Millisecond)
	c.expectNoPacket(t)
	// ACK repair7: repairs1..6 are now lost; repairs8..10 still remain
	// in flight. The real new cwnd4 therefore permits only one replay.
	if writes := privateRACKEpochACK(t, c, first, data, 6); writes != 1 || cc.lossCalls != 2 || s.rc.lossEpoch != 2 || s.SndCwnd != 4 {
		t.Fatalf("first new-loss window did not retain old in-flight pressure: writes=%d responses=%d epoch=%d cwnd=%d", writes, cc.lossCalls, s.rc.lossEpoch, s.SndCwnd)
	}
	var oldLater *segment
	for pos, seg := 0, s.writeList.Front(); seg != nil; pos, seg = pos+1, seg.Next() {
		if pos == 7 {
			oldLater = seg
			break
		}
	}
	if oldLater == nil || oldLater.lost || oldLater.lossEpoch != 1 || oldLater.xmitCount != 2 {
		t.Fatal("a genuinely not-yet-lost older-epoch replay was not retained")
	}
	// A later SACK at the SAME ingress time now declares that older replay
	// lost for the first time. It must not cut epoch2 a second time.
	if writes := privateRACKEpochACK(t, c, first, data, 9); writes != 3 || !oldLater.lost || oldLater.lossEpoch != 1 || cc.lossCalls != 2 || s.rc.lossEpoch != 2 || s.SndCwnd != 4 || s.Outstanding != 4 {
		t.Fatalf("late old-epoch loss caused another response or wrong available-flight repair: writes=%d old_lost=%t old_epoch=%d responses=%d current_epoch=%d cwnd=%d pipe=%d", writes, oldLater.lost, oldLater.lossEpoch, cc.lossCalls, s.rc.lossEpoch, s.SndCwnd, s.Outstanding)
	}
	// Now actual epoch2 replays are themselves lost a full RTT later.
	c.advance(100 * time.Millisecond)
	c.expectNoPacket(t)
	if writes := privateRACKEpochACK(t, c, first, data, 3); writes != 2 || cc.lossCalls != 3 || s.rc.lossEpoch != 3 || s.SndCwnd != 2 || s.Outstanding != 2 || s.writeList.Front().xmitCount != 4 {
		t.Fatalf("a genuinely later transmission-loss window failed to respond once: writes=%d responses=%d epoch=%d cwnd=%d pipe=%d head_xmits=%d", writes, cc.lossCalls, s.rc.lossEpoch, s.SndCwnd, s.Outstanding, s.writeList.Front().xmitCount)
	}
}

func TestPrivateRACKEpochReLossTimerRespondsOnce(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	cc, first, data, repairs := privateRACKEpochStart(t, c, ccReno)
	s := c.ep.snd
	if repairs != 10 {
		t.Fatal("timer control requires the real Reno ten-packet repair flight")
	}
	c.advance(100 * time.Millisecond)
	c.expectNoPacket(t)
	// An original, never-replayed packet below the prior suffix FACK
	// arrives late. The real ACK path detects reordering; no flag is set.
	if writes := privateRACKEpochACK(t, c, first, data, 13); writes != 0 || !s.rc.Reord || cc.lossCalls != 1 {
		t.Fatal("actual late original did not establish the real reorder allowance")
	}
	// ACK an actual replay. Remaining replays are not yet time-lost; a
	// newly free slot may repair one still-known original loss.
	if writes := privateRACKEpochACK(t, c, first, data, 9); writes != 1 || cc.lossCalls != 1 || !s.reorderTimer.enabled() || s.rc.ReoWnd <= 0 {
		t.Fatal("actual replay feedback did not defer re-loss to the real reorder timer")
	}
	deadline := s.reorderTimer.target
	c.advance(deadline.Sub(c.clock.NowMonotonic()) - time.Nanosecond)
	c.expectNoPacket(t)
	if cc.lossCalls != 1 || s.writeList.Front().lost || s.writeList.Front().xmitCount != 2 {
		t.Fatal("retransmission was declared lost before its actual reorder deadline")
	}
	c.advance(time.Nanosecond)
	// The one still-in-flight newer replay consumes a slot of reduced
	// cwnd5; exactly four actual retransmissions may now be dispatched.
	for index := range 4 {
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data[index])
	}
	c.expectNoPacket(t)
	if cc.lossCalls != 2 || cc.rtoCalls != 0 || s.rc.lossEpoch != 2 || s.SndCwnd != 5 || s.Outstanding != 5 || s.writeList.Front().xmitCount != 3 || c.ep.stack.Stats().TCP.Timeouts.Value() != 0 {
		t.Fatalf("actual timer did not apply the real bounded second response: responses=%d RTOs=%d epoch=%d cwnd=%d pipe=%d", cc.lossCalls, cc.rtoCalls, s.rc.lossEpoch, s.SndCwnd, s.Outstanding)
	}
	// A stale callback entry has no live expiry; repeating old ACK facts
	// cannot manufacture another current-epoch false→true loss.
	if err := s.rc.reorderTimerExpired(); err != nil {
		t.Fatalf("stale timer callback: %s", err)
	}
	if writes := privateRACKEpochACK(t, c, first, data, 9); writes != 0 || cc.lossCalls != 2 || s.rc.lossEpoch != 2 || s.SndCwnd != 5 {
		t.Fatal("stale timer/repeated ACK cut the same loss window again")
	}
}

func TestPrivateRACKEpochRTOAndTLPEntry(t *testing.T) {
	for _, finish := range []string{"RTO", "TLP_ACK"} {
		func() {
			t.Logf("recovery_entry_case=%s", finish)
			c := newPTOTestContext(t)
			c.ep.mu.Lock()
			defer c.ep.mu.Unlock()
			s := c.ep.snd
			cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
			s.cc = cc
			first := s.SndNxt
			data := bytes.Repeat([]byte{0xd4}, ptoTestPayloadSize)
			for index := range 3 {
				c.write(data)
				c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data)
			}
			c.advance(s.probeTimer.target.Sub(c.clock.NowMonotonic()))
			c.expectPacket(t, first.Add(2*ptoTestPayloadSize), data)
			c.expectNoPacket(t)
			if s.rc.lossEpoch != 0 || !s.rc.tlpRxtOut || cc.lossCalls != 0 || cc.rtoCalls != 0 {
				t.Fatal("unacknowledged TLP was treated as a congestion response")
			}
			if finish == "RTO" {
				c.advance(s.resendTimer.target.Sub(c.clock.NowMonotonic()))
				c.expectPacket(t, first, data)
				c.expectNoPacket(t)
				if cc.rtoCalls != 1 || cc.lossCalls != 0 || s.rc.lossEpoch != 1 || s.writeList.Front().lossEpoch != 1 || s.writeList.Front().Next().lossEpoch != 0 || s.FastRecovery.Active || s.state != tcpip.RTORecovery || s.SndCwnd != 1 {
					t.Fatal("real RTO did not separate its actual replay from old retained epoch")
				}
			} else {
				c.advance(100 * time.Millisecond)
				c.receive(t, s.SndNxt, s.SndWnd, nil)
				c.expectNoPacket(t)
				if cc.lossCalls != 1 || cc.rtoCalls != 0 || s.rc.lossEpoch != 1 || s.rc.tlpRxtOut || s.Outstanding != 0 || s.writeList.Front() != nil {
					t.Fatal("real TLP completion did not advance exactly one congestion epoch")
				}
				c.receive(t, s.SndUna, s.SndWnd, nil)
				c.expectNoPacket(t)
				if cc.lossCalls != 1 || s.rc.lossEpoch != 1 {
					t.Fatal("repeated TLP ACK advanced another congestion epoch")
				}
			}
		}()
	}
}

// These metadata controls deliberately exercise the generation primitive
// directly; the composed roots above prove real loss/CC inference.
func TestPrivateRACKEpochEqualClockCloneWrapAndPool(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	s := c.ep.snd
	seg := privateRACKRetainedGSO(c, false)
	seg.lossEpoch = 7
	s.rc.lossEpoch = 8
	s.splitSeg(seg, ptoTestPayloadSize)
	remainder := seg.Next()
	if remainder == nil || seg.lossEpoch != 7 || remainder.lossEpoch != 7 {
		t.Fatal("clone/split changed the prior transmission epoch")
	}
	originalTime := seg.xmitTime
	s.resendSegment()
	c.expectPacket(t, seg.sequenceNumber, bytes.Repeat([]byte{0xab}, ptoTestPayloadSize))
	c.expectNoPacket(t)
	if seg.lossEpoch != 8 || remainder.lossEpoch != 7 || seg.xmitTime != originalTime || remainder.xmitTime != originalTime {
		t.Fatal("equal-clock actual replay did not distinguish old and new send epochs")
	}
	// Force the finite integer boundary without billions of loss windows.
	// Old stamp1 must not alias the new epoch1 after wrap.
	s.rc.lossEpoch = ^uint32(0)
	seg.lossEpoch = 1
	remainder.lossEpoch = ^uint32(0)
	s.rc.advanceLossEpoch()
	if s.rc.lossEpoch != 1 || seg.lossEpoch != 0 || remainder.lossEpoch != 0 {
		t.Fatal("epoch wrap silently aliased retained older flight")
	}
	s.resendSegment()
	c.expectPacket(t, seg.sequenceNumber, bytes.Repeat([]byte{0xab}, ptoTestPayloadSize))
	c.expectNoPacket(t)
	if seg.lossEpoch != 1 || remainder.lossEpoch != 0 {
		t.Fatal("actual post-wrap replay failed to establish the new generation")
	}
	for range 8 {
		lease := newOutgoingSegment(c.ep.ID, c.clock, buffer.MakeWithData([]byte{1}), 0)
		if lease.lossEpoch != 0 {
			lease.DecRef()
			t.Fatal("fresh pooled segment lease retained a prior loss epoch")
		}
		lease.lossEpoch = ^uint32(0)
		lease.DecRef()
	}
}

func TestPrivateRACKEpochNonRACKRemainsInert(t *testing.T) {
	c := newPTOTestContext(t)
	c.ep.mu.Lock()
	defer c.ep.mu.Unlock()
	c.ep.tcpRecovery = 0
	s := c.ep.snd
	cc := &privateRACKSafetyCC{congestionControl: s.cc, snd: s}
	s.cc = cc
	warmStart := s.SndNxt
	data := bytes.Repeat([]byte{0xe5}, ptoTestPayloadSize)
	c.write(data)
	c.expectPacket(t, warmStart, data)
	c.advance(100 * time.Millisecond)
	c.receive(t, s.SndNxt, s.SndWnd, nil)
	c.expectNoPacket(t)
	first := s.SndNxt
	for index := range 3 {
		c.write(data)
		c.expectPacket(t, first.Add(seqnum.Size(index*ptoTestPayloadSize)), data)
	}
	c.advance(100 * time.Millisecond)
	for count := 1; count <= 2; count++ {
		privateRACKSuffixACK(t, c, first, header.SACKBlock{Start: first.Add(ptoTestPayloadSize), End: first.Add(seqnum.Size((count + 1) * ptoTestPayloadSize))})
		if count == 1 {
			c.expectNoPacket(t)
		}
	}
	c.expectPacket(t, first, data)
	c.expectNoPacket(t)
	if cc.lossCalls != 1 || cc.rtoCalls != 0 || !s.FastRecovery.Active || s.rc.lossEpoch != 0 {
		t.Fatal("legacy RFC6675 response changed or advanced a RACK epoch")
	}
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg.lossEpoch != 0 {
			t.Fatal("non-RACK actual send stamped epoch metadata")
		}
	}
}
