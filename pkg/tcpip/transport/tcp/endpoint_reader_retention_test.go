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

// A completed endpoint write must not keep its caller's backing allocation
// alive through the reusable copy reader while ordinary close timers run.
package tcp

import (
	"bytes"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// The real write path copies a segment from a large caller allocation, preserves
// its bytes after caller mutation, and releases the cached source before and
// during fin-wait-2. Receive work is synchronous and the clock never advances.
func TestTcpEndpointWriteReleasesCachedReader(t *testing.T) {
	var endpoint *Endpoint
	t.Cleanup(func() {
		// Registered first, this runs after the fixture aborts the endpoint and
		// stack.Destroy joins its workers.
		if endpoint == nil {
			return
		}
		for _, dangling := range tcpip.GetDanglingEndpoints() {
			if dangling == endpoint {
				t.Error("fixture teardown left its endpoint dangling")
			}
		}
	})
	c := newPTOTestContext(t)
	endpoint = c.ep

	endpoint.LockUser()
	cachedReader := endpoint.limRdr
	sequence := endpoint.snd.SndNxt
	endpoint.UnlockUser()
	if cachedReader == nil {
		t.Fatal("new endpoint has no reusable copy reader")
	}

	assertReaderReleased := func() {
		t.Helper()
		endpoint.LockUser()
		sameReader := endpoint.limRdr == cachedReader
		var retainedSource io.Reader
		if endpoint.limRdr != nil {
			retainedSource = endpoint.limRdr.R
		}
		endpoint.UnlockUser()
		if !sameReader {
			t.Error("write discarded the reusable copy reader")
		}
		if retainedSource != nil {
			t.Error("endpoint cached reader retained the caller's source")
		}
	}

	callerPayload := bytes.Repeat([]byte{0x5a}, 128*1024)
	expectedPayload := bytes.Clone(callerPayload[:ptoTestPayloadSize])
	source := bytes.NewReader(callerPayload[:ptoTestPayloadSize])
	n, err := endpoint.Write(source, tcpip.WriteOptions{})
	if n != int64(len(expectedPayload)) || err != nil {
		t.Fatalf("write = (%d, %v), want (%d, nil)", n, err, len(expectedPayload))
	}
	if source.Len() != 0 {
		t.Errorf("write left %d source bytes unread", source.Len())
	}
	assertReaderReleased()

	// Reading the actual emitted packet after caller mutation proves that the
	// endpoint owns a copy; removing the cached source cannot remove that data.
	for i := range callerPayload {
		callerPayload[i] = 0xa5
	}
	c.expectPacket(t, sequence, expectedPayload)
	queuedBytes, dataAcknowledged := func() (int, bool) {
		endpoint.LockUser()
		defer endpoint.UnlockUser()
		c.receive(t, sequence.Add(ptoTestPayloadSize), endpoint.snd.SndWnd, nil)
		endpoint.sndQueueInfo.sndQueueMu.Lock()
		queuedBytes := endpoint.sndQueueInfo.SndBufUsed
		endpoint.sndQueueInfo.sndQueueMu.Unlock()
		return queuedBytes, endpoint.snd.writeList.Front() == nil
	}()
	if queuedBytes != 0 || !dataAcknowledged {
		t.Fatalf("acknowledged data remains queued: bytes = %d, list empty = %t", queuedBytes, dataAcknowledged)
	}

	endpoint.Close()
	c.expectPacket(t, sequence.Add(ptoTestPayloadSize), nil)
	state, closed, timerArmed := func() (EndpointState, bool, bool) {
		endpoint.LockUser()
		defer endpoint.UnlockUser()
		// Processing the final acknowledgement under the endpoint lock is the
		// barrier: the state and its orphan timer are installed before inspection.
		c.receive(t, sequence.Add(ptoTestPayloadSize+1), endpoint.snd.SndWnd, nil)
		return endpoint.EndpointState(), endpoint.closed, endpoint.finWait2Timer != nil
	}()
	if state != StateFinWait2 || !closed || !timerArmed {
		t.Fatalf("after final acknowledgement: state = %s, closed = %t, timer armed = %t, want fin-wait-2, true, true", state, closed, timerArmed)
	}
	assertReaderReleased()
	c.expectNoPacket(t)
}
