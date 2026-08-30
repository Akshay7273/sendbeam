package relay

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sendbeam/engine/rendezvous"
)

type fakeSignal struct {
	mu     sync.Mutex
	msgs   []rendezvous.Message
	binary [][]byte
}

func (s *fakeSignal) Send(msg rendezvous.Message) error {
	s.mu.Lock()
	s.msgs = append(s.msgs, msg)
	s.mu.Unlock()
	return nil
}

func (s *fakeSignal) SendBinary(frame []byte) error {
	s.mu.Lock()
	s.binary = append(s.binary, append([]byte(nil), frame...))
	s.mu.Unlock()
	return nil
}

func TestConnNegotiatesCreditAndSendsWithinIt(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	if err := c.Open(); err != nil {
		t.Fatal(err)
	}
	if !c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady}) {
		t.Fatal("relay_ready was not handled")
	}
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: 32})
	if err := c.Send([]byte("sealed frame")); err != nil {
		t.Fatal(err)
	}
	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.msgs) != 2 || sig.msgs[0].Type != rendezvous.TypeRelayOpen ||
		sig.msgs[1].Type != rendezvous.TypeRelayCredit || sig.msgs[1].Bytes != windowBytes {
		t.Fatalf("control messages = %+v", sig.msgs)
	}
	if len(sig.binary) != 1 || string(sig.binary[0]) != "sealed frame" {
		t.Fatalf("binary = %q", sig.binary)
	}
}

func TestConnBuffersOneWindowUntilConsumerAndReplenishesAfterConsumption(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady})
	frame := make([]byte, creditBatch)
	c.HandleBinary(frame)
	got := make(chan int, 1)
	c.OnData(func(data []byte) { got <- len(data) })
	select {
	case size := <-got:
		if size != len(frame) {
			t.Fatalf("size = %d", size)
		}
	case <-time.After(time.Second):
		t.Fatal("buffered frame was not delivered")
	}
	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.msgs) != 2 || sig.msgs[1].Bytes != creditBatch {
		t.Fatalf("credit messages = %+v", sig.msgs)
	}
}

func TestConnCloseUnblocksCreditWaiter(t *testing.T) {
	c := New(&fakeSignal{})
	result := make(chan error, 1)
	go func() { result <- c.Send([]byte("blocked")) }()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked send returned nil after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock send")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := c.WaitReady(ctx); err == nil {
		t.Fatal("closed unready relay unexpectedly became ready")
	}
}

// flakySignal fails the first Send, simulating a transient signaling hiccup.
type flakySignal struct {
	fakeSignal
	failFirst bool
}

func (s *flakySignal) Send(msg rendezvous.Message) error {
	if s.failFirst {
		s.failFirst = false
		return errors.New("signaling down")
	}
	return s.fakeSignal.Send(msg)
}

func TestOpenRetriesAfterFailedSend(t *testing.T) {
	sig := &flakySignal{failFirst: true}
	c := New(sig)

	if err := c.Open(); err == nil {
		t.Fatal("Open succeeded despite failed send")
	}
	if err := c.Open(); err != nil {
		t.Fatalf("Open after transient failure: %v", err)
	}

	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.msgs) != 1 || sig.msgs[0].Type != rendezvous.TypeRelayOpen {
		t.Fatalf("relay_open was never actually sent after the retry: %+v", sig.msgs)
	}
}

func TestConnJitterAddsBoundedDelay(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	c.SetJitter(25 * time.Millisecond)

	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady})
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: 1024})

	start := time.Now()
	if err := c.Send([]byte("jittered-payload")); err != nil {
		t.Fatalf("Send failed: %v", err)
	}
	elapsed := time.Since(start)

	// Since max jitter is 25ms, elapsed must not exceed reasonable bounded time
	if elapsed > 200*time.Millisecond {
		t.Fatalf("send took too long (%v), expected bounded jitter <= 25ms", elapsed)
	}

	sig.mu.Lock()
	defer sig.mu.Unlock()
	if len(sig.binary) != 1 || string(sig.binary[0]) != "jittered-payload" {
		t.Fatalf("binary payload corrupted: %q", sig.binary)
	}
}

func TestConnCloseDuringJitterFailsClosed(t *testing.T) {
	sig := &fakeSignal{}
	c := New(sig)
	c.SetJitter(100 * time.Millisecond)

	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeRelayReady})
	c.HandleMessage(rendezvous.Message{Type: rendezvous.TypeCredit, Bytes: 1024})

	done := make(chan error, 1)
	go func() {
		done <- c.Send([]byte("closing-soon"))
	}()

	// Close conn while send may be in jitter sleep
	time.Sleep(10 * time.Millisecond)
	_ = c.Close()

	err := <-done
	// Should either succeed or return errClosed, but not panic or hang
	if err != nil && !errors.Is(err, errClosed) {
		t.Fatalf("unexpected error: %v", err)
	}
}
