// Private minimal qualification: real state roundtrip and compiler-measured
// before/after layouts. The old shadows copy exact frozen pre-epoch fields.
package tcp

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type privateRACKEpochOldSegment struct {
	segmentEntry
	segmentRefs
	ep             *Endpoint
	qFlags         queueFlags
	id             stack.TransportEndpointID `state:"manual"`
	pkt            *stack.PacketBuffer
	sequenceNumber seqnum.Value
	ackNumber      seqnum.Value
	flags          header.TCPFlags
	window         seqnum.Size
	csum           uint16
	csumValid      bool
	parsedOptions  header.TCPOptions
	options        []byte `state:".([]byte)"`
	hasNewSACKInfo bool
	rcvdTime       tcpip.MonotonicTime
	xmitTime       tcpip.MonotonicTime
	xmitCount      uint32
	acked          bool
	dataMemSize    int
	lost           bool
}

type privateRACKEpochOldControl struct {
	TCPRACKState
	exitedRecovery bool
	minRTT         time.Duration
	tlpRxtOut      bool
	tlpHighRxt     seqnum.Value
	snd            *sender
}

type privateRACKEpochOldSender struct {
	TCPSenderState
	ep                            *Endpoint
	finSent                       bool
	lr                            lossRecovery
	firstRetransmittedSegXmitTime tcpip.MonotonicTime
	zeroWindowProbing             bool   `state:"nosave"`
	unackZeroWindowProbes         uint32 `state:"nosave"`
	writeNext                     *segment
	writeList                     protectedWriteList
	resendTimer                   timer `state:"nosave"`
	rtt                           rtt
	minRTO                        time.Duration
	maxRTO                        time.Duration
	maxRetries                    uint32
	gso                           bool
	state                         tcpip.CongestionControlState
	cc                            congestionControl
	rc                            privateRACKEpochOldControl
	reorderTimer                  timer `state:"nosave"`
	probeTimer                    timer `state:"nosave"`
	spuriousRecovery              bool
	retransmitTS                  uint32
	startCork                     bool
	corkTimer                     timer `state:"nosave"`
}

func TestPrivateRACKEpochMeasuresRetainedFootprint(t *testing.T) {
	oldSegment, newSegment := int(unsafe.Sizeof(privateRACKEpochOldSegment{})), int(unsafe.Sizeof(segment{}))
	oldControl, newControl := int(unsafe.Sizeof(privateRACKEpochOldControl{})), int(unsafe.Sizeof(rackControl{}))
	oldSender, newSender := int(unsafe.Sizeof(privateRACKEpochOldSender{})), int(unsafe.Sizeof(sender{}))
	if segSize != newSegment || SegOverheadSize != newSegment+stack.PacketBufferStructSize+header.IPv4MaximumHeaderSize {
		t.Fatal("retained segment memory accounting does not use the actual new compiler size")
	}
	// A single uint32 may consume alignment padding or increase the enclosing
	// size. Measure it; do not assume a zero-cost field or change a budget.
	for _, change := range []struct {
		name          string
		before, after int
	}{
		{name: "segment", before: oldSegment, after: newSegment},
		{name: "rack", before: oldControl, after: newControl},
		{name: "sender", before: oldSender, after: newSender},
	} {
		if change.after < change.before || change.after-change.before > int(unsafe.Sizeof(uint64(0))) {
			t.Fatalf("unexpected %s layout growth: before=%d after=%d", change.name, change.before, change.after)
		}
	}
	t.Logf("RACK_EPOCH_COMPILER_FOOTPRINT: pointer_bytes=%d segment_old=%d new=%d delta=%d rack_old=%d new=%d delta=%d sender_old=%d new=%d delta=%d SegOverheadSize=%d; no allocation or platform peak claim", unsafe.Sizeof(uintptr(0)), oldSegment, newSegment, newSegment-oldSegment, oldControl, newControl, newControl-oldControl, oldSender, newSender, newSender-oldSender, SegOverheadSize)
}

func TestPrivateRACKEpochStateRoundTripAndFieldOrder(t *testing.T) {
	for _, value := range []any{&segment{}, &rackControl{}} {
		typ := reflect.TypeOf(value).Elem()
		var declared []string
		for index := range typ.NumField() {
			field := typ.Field(index)
			if tag := field.Tag.Get("state"); tag == "manual" || tag == "nosave" {
				continue
			}
			declared = append(declared, field.Name)
		}
		var encoded []string
		switch v := value.(type) {
		case *segment:
			encoded = v.StateFields()
		case *rackControl:
			encoded = v.StateFields()
		}
		if !reflect.DeepEqual(declared, encoded) {
			t.Fatalf("%s declaration order differs from private state metadata: declared=%v encoded=%v", typ, declared, encoded)
		}
	}
	var saved bytes.Buffer
	originalSegment := &segment{lossEpoch: 123, xmitCount: 3}
	if _, err := state.Save(context.Background(), &saved, &originalSegment); err != nil {
		t.Fatalf("save segment epoch: %s", err)
	}
	var restoredSegment *segment
	if _, err := state.Load(context.Background(), &saved, &restoredSegment); err != nil {
		t.Fatalf("load segment epoch: %s", err)
	}
	if restoredSegment == nil || restoredSegment.lossEpoch != 123 || restoredSegment.xmitCount != 3 {
		t.Fatal("segment latest-send epoch was not restored exactly")
	}
	saved.Reset()
	originalRack := &rackControl{lossEpoch: 456}
	if _, err := state.Save(context.Background(), &saved, &originalRack); err != nil {
		t.Fatalf("save rack epoch: %s", err)
	}
	var restoredRack *rackControl
	if _, err := state.Load(context.Background(), &saved, &restoredRack); err != nil {
		t.Fatalf("load rack epoch: %s", err)
	}
	if restoredRack == nil || restoredRack.lossEpoch != 456 {
		t.Fatal("per-flow congestion-response epoch was not restored exactly")
	}
}
