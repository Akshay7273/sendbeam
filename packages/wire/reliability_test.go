// V20-PR08: measured reliability evidence — slow-sink backpressure.
//
// A slow disk must cause backpressure, never unbounded memory growth, and the
// transfer must still complete byte-identical. This drives the real wire
// Sender/Receiver pair over the in-memory loopback with a throttled Sink:
// every Write sleeps, simulating a disk that sustains ~2 MiB/s. The test
// asserts byte identity, a generous time budget, and a bounded heap-growth
// budget across the run.
package wire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// throttledSink wraps a Sink and paces writes to the given byte rate,
// simulating a slow disk. The throttle is byte-proportional so it holds
// regardless of the writer's chunking.
type throttledSink struct {
	inner       Sink
	bytesPerSec int64
}

func (s *throttledSink) Write(offset int64, b []byte) error {
	if s.bytesPerSec > 0 && len(b) > 0 {
		time.Sleep(time.Duration(int64(len(b)) * int64(time.Second) / s.bytesPerSec))
	}
	return s.inner.Write(offset, b)
}

func (s *throttledSink) Close() error              { return s.inner.Close() }
func (s *throttledSink) Abort(reason string) error { return s.inner.Abort(reason) }

type slowSinkMeasurement struct {
	Scenario       string  `json:"scenario"`
	PayloadBytes   int64   `json:"payload_bytes"`
	ThrottleMiBs   float64 `json:"throttle_mib_s"`
	TotalMs        int64   `json:"total_ms"`
	ThroughputMiBs float64 `json:"throughput_mib_s"`
	HeapGrowthMiB  float64 `json:"heap_growth_mib"`
	DigestMatch    bool    `json:"digest_match"`
	Budget         string  `json:"budget"`
	Pass           bool    `json:"pass"`
	Note           string  `json:"note,omitempty"`
}

// TestReliability_SlowSink measures a 64 MiB transfer into a sink throttled
// to ~2 MiB/s: it must complete byte-identical without unbounded heap growth.
func TestReliability_SlowSink(t *testing.T) {
	const size = 64 << 20
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*41 + 3)
	}

	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	inner := &MemorySink{}
	// Simulate a ~2 MiB/s disk.
	sink := &throttledSink{inner: inner, bytesPerSec: 2 << 20}

	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }

	sender := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "slow.bin", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:      func(f []byte) error { s2r <- cp(f); return nil },
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 1 << 20,
		FrameSize: 16 << 10,
		Window:    8,
	})
	receiver := NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { r2s <- cp(f); return nil },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
	})

	go func() {
		for f := range s2r {
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()

	var heapBefore, heapAfter uint64
	{
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		heapBefore = ms.HeapAlloc
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(ctx); runErrCh <- e }()

	recvRes, recvErr := receiver.Wait(ctx)
	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(10 * time.Second):
		t.Fatal("sender.Run did not return after the receiver settled")
	}
	elapsed := time.Since(start)
	close(s2r)
	close(r2s)

	{
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		heapAfter = ms.HeapAlloc
	}

	m := slowSinkMeasurement{
		Scenario:     "slow-sink",
		PayloadBytes: int64(size),
		ThrottleMiBs: 2,
		TotalMs:      elapsed.Milliseconds(),
		Budget:       "complete < 300s, digest match, heap growth < 512 MiB",
	}
	if runErr != nil || recvErr != nil {
		m.Note = fmt.Sprintf("runErr=%v recvErr=%v", runErr, recvErr)
		emitSlowSink(t, m)
		return
	}
	m.ThroughputMiBs = float64(size) / elapsed.Seconds() / (1 << 20)
	m.HeapGrowthMiB = float64(int64(heapAfter)-int64(heapBefore)) / (1 << 20)
	want := sha256.Sum256(data)
	m.DigestMatch = bytes.Equal(inner.Bytes(), data) && recvRes.Digest == hex.EncodeToString(want[:])
	m.Pass = m.DigestMatch && elapsed < 5*time.Minute && m.HeapGrowthMiB < 512
	emitSlowSink(t, m)
}

func emitSlowSink(t *testing.T, m slowSinkMeasurement) {
	t.Helper()
	data, _ := json.Marshal(m)
	t.Logf("RELIABILITY %s", data)
	if !m.Pass {
		t.Errorf("scenario %s failed its budget %q", m.Scenario, m.Budget)
	}
}

// TestReliability_WireCutover measures a mid-transfer path cutover at the
// wire layer: 32 MiB over the "direct" channel pair, then an atomic switch
// to the "relay" pair at 50% acked bytes (Receiver/Sender.TransportChanged
// before any new-path frame is delivered, old-path tail dropped — the same
// contract production's supervisor enforces). The transfer must complete
// byte-identical without restarting at byte zero. Unlike the driver-level
// cutover, this needs no UDP and is deterministic in any sandbox.
func TestReliability_WireCutover(t *testing.T) {
	const size = 32 << 20
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*29 + 5)
	}
	keys, err := DeriveTransferKeys(loopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}
	link := newCutoverLink()

	const cutAfterBytes = int64(size) / 2
	var receiver *Receiver
	sender := NewSender(SenderOptions{
		File:      BytesSource(data, FileMeta{Name: "cutover.bin", Size: int64(len(data)), Mime: "application/octet-stream", LastModified: 1}, 0),
		Send:      func(f []byte) error { return link.route(dirS2R, f) },
		SendDir:   keys.O2J,
		RecvDir:   keys.J2O,
		BlockSize: 1 << 20,
		FrameSize: 16 << 10,
		Window:    8,
	})
	var recvMu sync.Mutex
	cutRequested := make(chan struct{}, 1)
	cutDone := make(chan struct{})
	var cutOnce sync.Once
	var cutAt int64
	doCut := func(acked int64) {
		cutOnce.Do(func() {
			recvMu.Lock()
			defer recvMu.Unlock()
			cutAt = acked
			link.switchPath()
			receiver.TransportChanged()
			sender.TransportChanged()
			close(cutDone)
		})
	}
	receiver = NewReceiver(ReceiverOptions{
		Send:    func(f []byte) error { return link.route(dirR2S, f) },
		SendDir: keys.J2O,
		RecvDir: keys.O2J,
		Sink:    sink,
		OnProgress: func(acked int64) {
			if acked >= cutAfterBytes {
				select {
				case cutRequested <- struct{}{}:
				default:
				}
			}
		},
	})
	go func() {
		for {
			select {
			case <-cutRequested:
				doCut(cutAfterBytes)
				select {
				case <-cutDone:
					return
				default:
				}
			case <-cutDone:
				return
			}
		}
	}()

	var stop int32
	drain := func(ch <-chan []byte, fn func([]byte)) {
		for {
			select {
			case f := <-ch:
				fn(f)
			default:
				if atomic.LoadInt32(&stop) == 1 {
					return
				}
				time.Sleep(time.Millisecond)
			}
		}
	}
	go drain(link.oldS2R, func(f []byte) {
		recvMu.Lock()
		defer recvMu.Unlock()
		select {
		case <-cutDone:
			return
		default:
		}
		receiver.Handle(f)
	})
	go drain(link.oldR2S, sender.Handle)
	go drain(link.newS2R, func(f []byte) {
		recvMu.Lock()
		defer recvMu.Unlock()
		receiver.Handle(f)
	})
	go drain(link.newR2S, sender.Handle)

	m := wireCutoverMeasurement{Scenario: "wire-cutover", PayloadBytes: int64(size)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	runErrCh := make(chan error, 1)
	go func() { _, e := sender.Run(ctx); runErrCh <- e }()
	recvResCh := make(chan ReceiveResult, 1)
	recvErrCh := make(chan error, 1)
	go func() { r, e := receiver.Wait(ctx); recvResCh <- r; recvErrCh <- e }()

	var runErr error
	select {
	case runErr = <-runErrCh:
	case <-time.After(5 * time.Minute):
		t.Fatal("sender.Run did not return within deadline")
	}
	recvRes := <-recvResCh
	recvErr := <-recvErrCh
	elapsed := time.Since(start)
	atomic.StoreInt32(&stop, 1)

	m.TotalMs = elapsed.Milliseconds()
	m.Budget = "complete < 300s after mid-transfer path cutover, byte-identical"
	m.CutAtBytes = cutAt
	if runErr != nil || recvErr != nil {
		m.Note = fmt.Sprintf("runErr=%v recvErr=%v", runErr, recvErr)
		emitWireCutover(t, m)
		return
	}
	m.ThroughputMiBs = float64(size) / elapsed.Seconds() / (1 << 20)
	want := sha256.Sum256(data)
	m.DigestMatch = bytes.Equal(sink.Bytes(), data) && recvRes.Digest == hex.EncodeToString(want[:])
	m.Pass = m.DigestMatch && elapsed < 5*time.Minute && cutAt >= cutAfterBytes
	emitWireCutover(t, m)
}

type wireCutoverMeasurement struct {
	Scenario       string  `json:"scenario"`
	PayloadBytes   int64   `json:"payload_bytes"`
	CutAtBytes     int64   `json:"cut_at_bytes"`
	TotalMs        int64   `json:"total_ms"`
	ThroughputMiBs float64 `json:"throughput_mib_s"`
	DigestMatch    bool    `json:"digest_match"`
	Budget         string  `json:"budget"`
	Pass           bool    `json:"pass"`
	Note           string  `json:"note,omitempty"`
}

func emitWireCutover(t *testing.T, m wireCutoverMeasurement) {
	t.Helper()
	data, _ := json.Marshal(m)
	t.Logf("RELIABILITY %s", data)
	if !m.Pass {
		t.Errorf("scenario %s failed its budget %q", m.Scenario, m.Budget)
	}
}
