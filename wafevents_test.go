package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/deploys-app/api"
)

// fakePod emulates the controller's :9188 cursor endpoint (wire semantics of
// parapet-ingress-controller wafevent.NewHandler): bearer auth, boot-mismatch
// and future-cursor reset to the tail, oldest-first pages of at most max.
type fakePod struct {
	mu     sync.Mutex
	boot   string
	events []wafPodEvent // Seq of events[i] is i+1; ring eviction not modeled (not needed for cursor semantics)

	afterSeen []uint64 // after param of every authenticated request, in order
}

func (p *fakePod) handler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		p.mu.Lock()
		defer p.mu.Unlock()

		after, _ := strconv.ParseUint(r.FormValue("after"), 10, 64)
		if r.FormValue("boot") != p.boot {
			after = 0
		}
		if after > uint64(len(p.events)) {
			after = 0
		}
		p.afterSeen = append(p.afterSeen, after)

		max, _ := strconv.Atoi(r.FormValue("max"))
		events := p.events[after:]
		if max > 0 && len(events) > max {
			events = events[:max]
		}
		if events == nil {
			events = []wafPodEvent{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"boot":   p.boot,
			"next":   after + uint64(len(events)),
			"events": events,
		})
	})
}

// fakeCollector records SetWAFEvents calls and fails them while err is set.
// The embedded interface panics on any other method — nothing else may be
// called by the events syncer.
type fakeCollector struct {
	api.Collector

	mu    sync.Mutex
	err   error
	calls []*api.CollectorSetWAFEvents
}

func (c *fakeCollector) SetWAFEvents(_ context.Context, m *api.CollectorSetWAFEvents) (*api.Empty, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	c.calls = append(c.calls, m)
	return &api.Empty{}, nil
}

func (c *fakeCollector) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *fakeCollector) shippedIDs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ids []string
	for _, call := range c.calls {
		for _, it := range call.List {
			ids = append(ids, it.ID)
		}
	}
	return ids
}

type fakeAPI struct {
	api.Interface

	collector *fakeCollector
}

func (f fakeAPI) Collector() api.Collector { return f.collector }

const testWAFEventsToken = "test-waf-events-token"

// newWAFEventsFixture starts a fake pod endpoint and returns a syncer whose
// DNS hook resolves the target host to the httptest listener.
func newWAFEventsFixture(t *testing.T, pod *fakePod) (*wafEventsSyncer, *fakeCollector) {
	t.Helper()

	srv := httptest.NewServer(pod.handler(testWAFEventsToken))
	t.Cleanup(srv.Close)

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	collector := &fakeCollector{}
	s := &wafEventsSyncer{
		Target:     "parapet-pods.test.svc:" + port,
		Token:      testWAFEventsToken,
		Location:   "test-location",
		Client:     fakeAPI{collector: collector},
		HTTPClient: srv.Client(),
		lookupIP: func(_ context.Context, h string) ([]net.IP, error) {
			if h != "parapet-pods.test.svc" {
				return nil, fmt.Errorf("unexpected host %q", h)
			}
			return []net.IP{net.ParseIP(host)}, nil
		},
	}
	return s, collector
}

func testEvent(seq int, ruleID string) wafPodEvent {
	return wafPodEvent{
		ID:       fmt.Sprintf("01TESTULID%016d", seq),
		At:       1700000000 + int64(seq),
		Zone:     "parapet/zone-x",
		RuleID:   ruleID,
		Action:   "block",
		Status:   403,
		ClientIP: "192.0.2.7",
		Country:  "TH",
		ASN:      4750,
		Method:   "POST",
		Host:     "example.com",
		Path:     "/wp-login.php",
	}
}

func TestWAFEventsShipAndAdvanceCursor(t *testing.T) {
	t.Parallel()

	pod := &fakePod{
		boot: "boot-a",
		events: []wafPodEvent{
			testEvent(1, "123-abcdef"),
			testEvent(2, "no-project-prefix"), // global-scope straggler: consumed, not shipped
			testEvent(3, "123-abcdef"),
		},
	}
	s, collector := newWAFEventsFixture(t, pod)

	s.Run(context.Background())

	if len(collector.calls) != 1 {
		t.Fatalf("SetWAFEvents calls = %d, want 1", len(collector.calls))
	}
	call := collector.calls[0]
	if call.Location != "test-location" {
		t.Errorf("Location = %q, want test-location", call.Location)
	}
	if len(call.List) != 2 {
		t.Fatalf("shipped %d items, want 2 (non-attributable rule id skipped)", len(call.List))
	}
	it := call.List[0]
	src := pod.events[0]
	if it.ID != src.ID || it.ProjectID != 123 || it.RuleID != src.RuleID ||
		it.Action != src.Action || it.Status != src.Status || it.At != src.At ||
		it.ClientIP != src.ClientIP || it.Country != src.Country || it.ASN != src.ASN ||
		it.Method != src.Method || it.Host != src.Host || it.Path != src.Path {
		t.Errorf("shipped item %+v does not match source event %+v", it, src)
	}

	// Second tick: cursor advanced past everything, nothing re-shipped.
	s.Run(context.Background())

	if len(collector.calls) != 1 {
		t.Fatalf("SetWAFEvents calls after idle tick = %d, want 1", len(collector.calls))
	}
	if got := pod.afterSeen; len(got) != 2 || got[0] != 0 || got[1] != 3 {
		t.Errorf("after params = %v, want [0 3]", got)
	}
}

func TestWAFEventsFailedShipKeepsCursorAndRetriesIdempotently(t *testing.T) {
	t.Parallel()

	pod := &fakePod{
		boot:   "boot-a",
		events: []wafPodEvent{testEvent(1, "123-abcdef"), testEvent(2, "123-abcdef")},
	}
	s, collector := newWAFEventsFixture(t, pod)
	collector.setErr(errors.New("db down"))

	s.Run(context.Background())

	if len(collector.calls) != 0 {
		t.Fatalf("SetWAFEvents recorded %d successful calls during outage, want 0", len(collector.calls))
	}
	if cur := s.cursors[podIP(t, s)]; cur.next != 0 || cur.boot != "" {
		t.Fatalf("cursor advanced despite ship failure: %+v", cur)
	}

	// Recovery: the same range is re-polled and the same ULIDs re-shipped
	// (the apiserver dedupes them), then the cursor advances.
	collector.setErr(nil)
	s.Run(context.Background())

	if ids := collector.shippedIDs(); len(ids) != 2 || ids[0] != pod.events[0].ID || ids[1] != pod.events[1].ID {
		t.Fatalf("retry shipped ids %v, want the same two ULIDs", ids)
	}
	if got := pod.afterSeen; len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Errorf("after params = %v, want [0 0] (retry re-polls the same range)", got)
	}
	if cur := s.cursors[podIP(t, s)]; cur.next != 2 || cur.boot != "boot-a" {
		t.Errorf("cursor after successful retry = %+v, want next=2 boot=boot-a", cur)
	}
}

func TestWAFEventsBootMismatchReplaysFromTail(t *testing.T) {
	t.Parallel()

	pod := &fakePod{
		boot:   "boot-a",
		events: []wafPodEvent{testEvent(1, "123-abcdef")},
	}
	s, collector := newWAFEventsFixture(t, pod)

	s.Run(context.Background())

	// Pod restart: new boot id, cursor seq restarts.
	pod.mu.Lock()
	pod.boot = "boot-b"
	pod.events = []wafPodEvent{testEvent(9, "123-abcdef")}
	pod.mu.Unlock()

	s.Run(context.Background())

	if ids := collector.shippedIDs(); len(ids) != 2 || ids[1] != testEvent(9, "").ID {
		t.Fatalf("shipped ids = %v, want old event then post-restart event", ids)
	}
	if cur := s.cursors[podIP(t, s)]; cur.boot != "boot-b" || cur.next != 1 {
		t.Errorf("cursor = %+v, want boot=boot-b next=1", cur)
	}
}

func TestWAFEventsDrainsFullPagesWithinOneTick(t *testing.T) {
	t.Parallel()

	pod := &fakePod{boot: "boot-a"}
	for i := 1; i <= 5; i++ {
		pod.events = append(pod.events, testEvent(i, "123-abcdef"))
	}
	s, collector := newWAFEventsFixture(t, pod)
	s.readMax = 2

	s.Run(context.Background())

	// 5 events at page size 2 → pages of 2, 2, 1; each shipped before the
	// cursor advances to the next.
	if got := pod.afterSeen; len(got) != 3 || got[0] != 0 || got[1] != 2 || got[2] != 4 {
		t.Fatalf("after params = %v, want [0 2 4]", got)
	}
	if ids := collector.shippedIDs(); len(ids) != 5 {
		t.Fatalf("shipped %d events, want 5", len(ids))
	}
	if cur := s.cursors[podIP(t, s)]; cur.next != 5 {
		t.Errorf("cursor next = %d, want 5", cur.next)
	}
}

func TestWAFEventsForgetsStalePods(t *testing.T) {
	t.Parallel()

	pod := &fakePod{boot: "boot-a"}
	s, _ := newWAFEventsFixture(t, pod)

	resolveErr := false
	realLookup := s.lookupIP
	s.lookupIP = func(ctx context.Context, h string) ([]net.IP, error) {
		if resolveErr {
			return nil, errors.New("no such host")
		}
		return realLookup(ctx, h)
	}
	now := time.Now()
	s.now = func() time.Time { return now }

	s.Run(context.Background())
	if len(s.cursors) != 1 {
		t.Fatalf("cursors = %d, want 1", len(s.cursors))
	}

	// The pod stops resolving: a failed resolve must not touch cursors at all
	// (a DNS blip is not pod death), and a pod absent from a successful
	// resolve is kept for the grace window, then forgotten.
	resolveErr = true
	now = now.Add(11 * time.Minute)
	s.Run(context.Background())
	if len(s.cursors) != 1 {
		t.Fatalf("cursors after resolve error = %d, want 1 (kept)", len(s.cursors))
	}

	resolveErr = false
	s.lookupIP = func(context.Context, string) ([]net.IP, error) { return nil, nil }
	s.Run(context.Background())
	if len(s.cursors) != 0 {
		t.Fatalf("cursors after grace window = %d, want 0 (forgotten)", len(s.cursors))
	}
}

func TestWAFEventsStuckCursorStopsDrainLoop(t *testing.T) {
	t.Parallel()

	// A misbehaving endpoint that returns a full page without ever moving
	// (boot, next) must not pin the collector in a hot re-ship loop; the drain
	// gives up for the tick after the first repeat.
	var polls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"boot":   "boot-a",
			"next":   uint64(0),
			"events": []wafPodEvent{testEvent(1, "123-abcdef")},
		})
	}))
	defer srv.Close()

	host, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	collector := &fakeCollector{}
	s := &wafEventsSyncer{
		Target:     "stuck.test.svc:" + port,
		Token:      testWAFEventsToken,
		Location:   "test-location",
		Client:     fakeAPI{collector: collector},
		HTTPClient: srv.Client(),
		readMax:    1,
		lookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP(host)}, nil
		},
	}

	s.Run(context.Background())

	// Poll 1 establishes the (boot-a, 0) cursor; poll 2 repeats it and trips
	// the guard.
	if polls != 2 {
		t.Fatalf("polls = %d, want 2 (drain must stop once the cursor stops advancing)", polls)
	}
}

func TestWAFEventsPollUnauthorizedDoesNotAdvance(t *testing.T) {
	t.Parallel()

	pod := &fakePod{boot: "boot-a", events: []wafPodEvent{testEvent(1, "123-abcdef")}}
	s, collector := newWAFEventsFixture(t, pod)
	s.Token = "wrong-token"

	s.Run(context.Background())

	if len(collector.calls) != 0 {
		t.Fatalf("shipped %d calls with a rejected token, want 0", len(collector.calls))
	}
	if cur := s.cursors[podIP(t, s)]; cur == nil || cur.next != 0 {
		t.Errorf("cursor = %+v, want next=0", cur)
	}
}

// podIP returns the single resolved pod IP key of the fixture's cursor map.
func podIP(t *testing.T, s *wafEventsSyncer) string {
	t.Helper()
	ips, err := s.lookupIP(context.Background(), "parapet-pods.test.svc")
	if err != nil || len(ips) != 1 {
		t.Fatalf("fixture lookup: ips=%v err=%v", ips, err)
	}
	return ips[0].String()
}
