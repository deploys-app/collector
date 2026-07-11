package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/deploys-app/api"
)

const (
	// wafEventsReadMax is the page size requested from the controller cursor
	// endpoint (its own hard cap is 1000). It must stay ≤ api.WAFEventsMaxBatch
	// so one page always fits in one setWAFEvents call — shipping a page is
	// all-or-nothing, which keeps the cursor-advance rule simple.
	wafEventsReadMax = 1000

	// wafEventsForgetAfter is how long a pod IP may stop resolving before its
	// cursor is forgotten (SPEC-waf-events §F). Long enough to survive a DNS
	// blip or rolling restart re-listing; the ULID dedupe makes a wrongly
	// forgotten cursor merely wasteful, never incorrect.
	wafEventsForgetAfter = 10 * time.Minute
)

// Compile-time guard for the wafEventsReadMax ≤ WAFEventsMaxBatch invariant
// (negative array length if violated).
var _ [api.WAFEventsMaxBatch - wafEventsReadMax]struct{}

// wafEventsPage is the wire format of the controller's cursor endpoint
// (parapet-ingress-controller wafevent.NewHandler, SPEC-waf-events §C.3).
type wafEventsPage struct {
	Boot   string         `json:"boot"`
	Next   uint64         `json:"next"`
	Events []*wafPodEvent `json:"events"`
}

// wafPodEvent mirrors wafevent.Event's JSON (SPEC-waf-events §C.1). Zone is
// received but not shipped: the apiserver keys events by (location, project),
// and project comes from the rule-id prefix.
type wafPodEvent struct {
	ID       string `json:"id"`
	At       int64  `json:"at"`
	Zone     string `json:"zone"`
	RuleID   string `json:"ruleId"`
	Action   string `json:"action"`
	Status   int    `json:"status"`
	ClientIP string `json:"clientIp"`
	Country  string `json:"country"`
	ASN      int64  `json:"asn"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	Path     string `json:"path"`
}

// wafEventsCursor is the per-pod read position. It lives only in memory:
// losing it (collector restart) replays up to one ring of events, which the
// apiserver dedupes by ULID id.
type wafEventsCursor struct {
	boot string
	next uint64
	seen time.Time // last tick the pod IP resolved; drives forgetting
}

// wafEventsSyncer polls every parapet-ingress-controller pod's cursor
// endpoint (discovered via DNS A records of the controller headless service —
// no k8s client, mirroring how the prom scrape reaches its targets through a
// stable in-cluster address) and ships sampled WAF match events to
// collector.setWAFEvents. Events have no healing second source (unlike the
// usage loops, which re-query Prometheus each run), so the per-pod cursor
// advances ONLY after a successful handoff; a failed ship re-polls the same
// range next tick and the ULID dedupe makes the retry idempotent.
type wafEventsSyncer struct {
	Target     string // headless-service host:port, e.g. parapet-ingress-controller-pods.parapet.svc:9188
	Token      string // must match the controller's WAF_EVENTS_TOKEN
	Location   string
	Client     api.Interface
	HTTPClient *http.Client

	readMax  int                                                      // page size; test hook, defaults to wafEventsReadMax
	lookupIP func(ctx context.Context, host string) ([]net.IP, error) // test hook
	now      func() time.Time                                         // test hook

	cursors map[string]*wafEventsCursor // keyed by resolved pod IP
}

func (s *wafEventsSyncer) timeNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *wafEventsSyncer) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if s.lookupIP != nil {
		return s.lookupIP(ctx, host)
	}
	// "ip4" (A records only, SPEC-waf-events §C.4): on a dual-stack cluster a
	// dual lookup would return each pod twice (A + AAAA) and double every poll.
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// Run performs one poll tick: resolve the controller pods, drain each pod's
// ring from its remembered cursor, and forget pods that stopped resolving.
func (s *wafEventsSyncer) Run(ctx context.Context) {
	slog.Info("collector: sync waf events")

	host, port, err := net.SplitHostPort(s.Target)
	if err != nil {
		slog.Error("collector: sync waf events invalid target", "target", s.Target, "error", err)
		return
	}

	ips, err := s.resolve(ctx, host)
	if err != nil {
		slog.Error("collector: sync waf events resolve error", "host", host, "error", err)
		return
	}

	if s.cursors == nil {
		s.cursors = map[string]*wafEventsCursor{}
	}

	now := s.timeNow()
	for _, ip := range ips {
		cur := s.cursors[ip.String()]
		if cur == nil {
			cur = &wafEventsCursor{}
			s.cursors[ip.String()] = cur
		}
		cur.seen = now

		s.syncPod(ctx, net.JoinHostPort(ip.String(), port), cur)
	}

	for ip, cur := range s.cursors {
		if now.Sub(cur.seen) > wafEventsForgetAfter {
			delete(s.cursors, ip)
		}
	}
}

// syncPod drains one pod's ring: poll a page, ship it, and only then adopt
// the returned (boot, next) cursor. A full page means more may be buffered,
// so it polls again immediately rather than waiting a tick.
func (s *wafEventsSyncer) syncPod(ctx context.Context, addr string, cur *wafEventsCursor) {
	readMax := s.readMax
	if readMax <= 0 {
		readMax = wafEventsReadMax
	}

	for {
		page, err := s.poll(ctx, addr, cur, readMax)
		if err != nil {
			slog.Error("collector: sync waf events poll error", "addr", addr, "error", err)
			return
		}

		err = s.ship(ctx, page.Events)
		if err != nil {
			// Keep the old cursor: the same range is re-polled next tick and the
			// apiserver's ULID dedupe makes the resend idempotent. This is the
			// at-least-once delivery guarantee — a dropped batch here would be
			// gone for good once the cursor moves.
			slog.Error("collector: sync waf events ship error", "addr", addr, "error", err)
			return
		}

		progressed := page.Boot != cur.boot || page.Next != cur.next
		cur.boot = page.Boot
		cur.next = page.Next

		if len(page.Events) < readMax {
			return
		}
		if !progressed {
			// A full page that moved neither boot nor next can only repeat
			// forever; without this exit a misbehaving endpoint would pin the
			// collector in a hot re-ship loop inside one tick.
			slog.Error("collector: sync waf events cursor did not advance", "addr", addr)
			return
		}
	}
}

func (s *wafEventsSyncer) poll(ctx context.Context, addr string, cur *wafEventsCursor, readMax int) (*wafEventsPage, error) {
	q := url.Values{}
	q.Set("after", strconv.FormatUint(cur.next, 10))
	q.Set("boot", cur.boot)
	q.Set("max", strconv.Itoa(readMax))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/waf/events?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Drain whatever the decoder (or an early error return) leaves unread so
	// the transport can reuse the connection instead of dialing every poll.
	defer io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var page wafEventsPage
	err = json.NewDecoder(resp.Body).Decode(&page)
	if err != nil {
		return nil, err
	}
	return &page, nil
}

// ship attributes each event to its project via the rule-id prefix (same
// oracle as syncWAFUsage — this also drops any global-scope stragglers) and
// pushes the batch. Events that attribute to no project are consumed without
// shipping; they can never become shippable, so skipping them must not hold
// the cursor back.
func (s *wafEventsSyncer) ship(ctx context.Context, events []*wafPodEvent) error {
	req := api.CollectorSetWAFEvents{
		Location: s.Location,
	}
	for _, e := range events {
		m := reWAFRuleProject.FindStringSubmatch(e.RuleID)
		if m == nil {
			continue
		}
		projectID, _ := strconv.ParseInt(m[1], 10, 64)
		if projectID == 0 {
			continue
		}

		req.List = append(req.List, &api.CollectorWAFEventItem{
			ID:        e.ID,
			ProjectID: projectID,
			RuleID:    e.RuleID,
			Action:    e.Action,
			Status:    e.Status,
			At:        e.At,
			ClientIP:  e.ClientIP,
			Country:   e.Country,
			ASN:       e.ASN,
			Method:    e.Method,
			Host:      e.Host,
			Path:      e.Path,
		})
	}

	if len(req.List) == 0 {
		return nil
	}

	_, err := s.Client.Collector().SetWAFEvents(ctx, &req)
	return err
}
