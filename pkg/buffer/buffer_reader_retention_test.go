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

// Reusable copy readers must release borrowed sources on every return while
// preserving the copied bytes, read limit, and original error.
package buffer_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
)

// Adapts a deterministic source for the copy's error and no-read cases.
type retentionReaderFunc func([]byte) (int, error)

// Delegates each read to the test's source.
func (self retentionReaderFunc) Read(dst []byte) (int, error) {
	return self(dst)
}

// Exact copies cross chunk boundaries and reuse the same limiter without
// retaining any of the previous callers' sources.
func TestBufferReusableReaderReleasesSource(t *testing.T) {
	limitedReader := &io.LimitedReader{}
	for _, size := range []int{1, buffer.MaxChunkSize, 2*buffer.MaxChunkSize + 17} {
		func() {
			payload := bytes.Repeat([]byte{0x5a}, size)
			source := bytes.NewReader(payload)
			var copied buffer.Buffer
			defer copied.Release()

			n, err := copied.WriteFromReaderAndLimitedReader(source, int64(size), limitedReader)
			if n != int64(size) || err != nil {
				t.Fatalf("size %d: copy = (%d, %v), want (%d, nil)", size, n, err, size)
			}
			if got := copied.Flatten(); !bytes.Equal(got, payload) {
				t.Errorf("size %d: copied bytes differ from the source", size)
			}
			if source.Len() != 0 || limitedReader.N != 0 {
				t.Errorf("size %d: remaining source = %d, limit = %d, want both zero", size, source.Len(), limitedReader.N)
			}
			if limitedReader.R != nil {
				t.Errorf("size %d: reusable limiter retained the source after copying", size)
			}
		}()
	}
}

// A copy smaller than the source preserves the unread suffix and limit.
func TestBufferReusableReaderPreservesReadLimit(t *testing.T) {
	payload := []byte("synthetic prefix and unread suffix")
	source := bytes.NewReader(payload)
	limitedReader := &io.LimitedReader{}
	var copied buffer.Buffer
	defer copied.Release()
	const count = 16

	n, err := copied.WriteFromReaderAndLimitedReader(source, count, limitedReader)
	if n != count || err != nil {
		t.Fatalf("copy = (%d, %v), want (%d, nil)", n, err, count)
	}
	if got := copied.Flatten(); !bytes.Equal(got, payload[:count]) {
		t.Error("copied bytes differ from the requested prefix")
	}
	if source.Len() != len(payload)-count || limitedReader.N != 0 {
		t.Errorf("remaining source = %d, limit = %d, want %d and zero", source.Len(), limitedReader.N, len(payload)-count)
	}
	if limitedReader.R != nil {
		t.Error("reusable limiter retained the partially consumed source")
	}
}

// Errors before or after data retain the returned count, bytes, and exact error,
// but the reusable limiter must release the borrowed source in either case.
func TestBufferReusableReaderReleasesSourceOnError(t *testing.T) {
	readErr := errors.New("synthetic source failure")
	limitedReader := &io.LimitedReader{}
	for _, prefix := range [][]byte{nil, []byte("synthetic partial data")} {
		func() {
			source := retentionReaderFunc(func(dst []byte) (int, error) {
				if len(dst) == 0 {
					return 0, nil
				}
				return copy(dst, prefix), readErr
			})
			var copied buffer.Buffer
			defer copied.Release()
			const count = 64

			n, err := copied.WriteFromReaderAndLimitedReader(source, count, limitedReader)
			if n != int64(len(prefix)) || err != readErr {
				t.Fatalf("prefix length %d: copy = (%d, %v), want (%d, original error)", len(prefix), n, err, len(prefix))
			}
			if got := copied.Flatten(); !bytes.Equal(got, prefix) {
				t.Errorf("prefix length %d: copied bytes differ from the partial data", len(prefix))
			}
			if limitedReader.N != int64(count-len(prefix)) {
				t.Errorf("prefix length %d: remaining limit = %d, want %d", len(prefix), limitedReader.N, count-len(prefix))
			}
			if limitedReader.R != nil {
				t.Errorf("prefix length %d: reusable limiter retained the failed source", len(prefix))
			}
		}()
	}
}

// A zero-count call still releases an already populated source without reading
// the new source or changing the limiter's otherwise untouched count.
func TestBufferReusableReaderReleasesSourceWithoutRead(t *testing.T) {
	source := retentionReaderFunc(func([]byte) (int, error) {
		t.Fatal("zero-count copy read the source")
		return 0, nil
	})
	limitedReader := &io.LimitedReader{
		R: bytes.NewReader([]byte("synthetic previous source")),
		N: 23,
	}
	var copied buffer.Buffer
	defer copied.Release()

	n, err := copied.WriteFromReaderAndLimitedReader(source, 0, limitedReader)
	if n != 0 || err != nil || copied.Size() != 0 {
		t.Fatalf("zero-count copy = (%d, %v), buffer size = %d, want zero, nil, and zero", n, err, copied.Size())
	}
	if limitedReader.N != 23 {
		t.Errorf("untouched limit = %d, want 23", limitedReader.N)
	}
	if limitedReader.R != nil {
		t.Error("zero-count copy retained the previous source")
	}
}

// Callers without a reusable limiter keep the same copy behavior.
func TestBufferReaderWithoutReusableLimiter(t *testing.T) {
	payload := []byte("synthetic uncached copy")
	var copied buffer.Buffer
	defer copied.Release()

	n, err := copied.WriteFromReader(bytes.NewReader(payload), int64(len(payload)))
	if n != int64(len(payload)) || err != nil {
		t.Fatalf("copy = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if got := copied.Flatten(); !bytes.Equal(got, payload) {
		t.Error("uncached copy differs from the source")
	}
}
