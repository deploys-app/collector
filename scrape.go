package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deploys-app/api"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"golang.org/x/sync/semaphore"
)

const customMetricsConcurrency = 10

var (
	errEmptyMetricsBody = errors.New("empty metrics body")
	errBodyTooLarge     = errors.New("body too large")
)

// scrapeHTTPClient GETs platform-resolved scrape URLs. CheckRedirect refuses a
// different host so a 3xx cannot steer the collector off-cluster.
var scrapeHTTPClient = &http.Client{
	Timeout:       api.MetricSourceScrapeTimeout,
	CheckRedirect: sameHostRedirect,
}

func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("redirect to different host")
	}
	return nil
}

type scrapedSample struct {
	Series string // name or name{sortedLabels}, e.g. queue_depth{queue="email"}
	Type   string // gauge|counter|untyped — local only; ingest has no Type field
	Value  float64
}

type scrapeResult struct {
	Samples   []scrapedSample
	Truncated bool
	Err       error
}

func parsePromMetrics(body []byte, maxSeries int) scrapeResult {
	if len(body) == 0 {
		return scrapeResult{Err: errEmptyMetricsBody}
	}

	dec := expfmt.NewDecoder(bytes.NewReader(body), expfmt.NewFormat(expfmt.TypeTextPlain))
	var samples []scrapedSample
	for {
		var mf dto.MetricFamily
		err := dec.Decode(&mf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return scrapeResult{Err: err}
		}

		typ, ok := keptMetricType(mf.GetType())
		if !ok {
			continue
		}
		name := mf.GetName()
		for _, m := range mf.GetMetric() {
			v, ok := metricValue(typ, m)
			if !ok {
				continue
			}
			samples = append(samples, scrapedSample{
				Series: seriesKey(name, m.GetLabel()),
				Type:   typ,
				Value:  v,
			})
		}
	}

	slices.SortFunc(samples, func(a, b scrapedSample) int {
		return cmp.Compare(a.Series, b.Series)
	})
	truncated := false
	if len(samples) > maxSeries {
		samples = samples[:maxSeries]
		truncated = true
	}
	return scrapeResult{Samples: samples, Truncated: truncated}
}

func keptMetricType(t dto.MetricType) (string, bool) {
	switch t {
	case dto.MetricType_GAUGE:
		return api.MetricSourceSeriesTypeGauge, true
	case dto.MetricType_COUNTER:
		return api.MetricSourceSeriesTypeCounter, true
	case dto.MetricType_UNTYPED:
		return api.MetricSourceSeriesTypeUntyped, true
	default:
		// Drop histogram, gauge histogram, and summary families wholesale,
		// including their _bucket/_sum/_count children.
		return "", false
	}
}

func metricValue(typ string, m *dto.Metric) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch typ {
	case api.MetricSourceSeriesTypeGauge:
		if m.Gauge == nil {
			return 0, false
		}
		return m.GetGauge().GetValue(), true
	case api.MetricSourceSeriesTypeCounter:
		if m.Counter == nil {
			return 0, false
		}
		return m.GetCounter().GetValue(), true
	case api.MetricSourceSeriesTypeUntyped:
		if m.Untyped == nil {
			return 0, false
		}
		return m.GetUntyped().GetValue(), true
	default:
		return 0, false
	}
}

func seriesKey(name string, labels []*dto.LabelPair) string {
	ls := make([]*dto.LabelPair, 0, len(labels))
	for _, l := range labels {
		if l == nil || l.GetName() == "" || l.GetName() == "__name__" {
			continue
		}
		ls = append(ls, l)
	}
	if len(ls) == 0 {
		return name
	}
	slices.SortFunc(ls, func(a, b *dto.LabelPair) int {
		return cmp.Compare(a.GetName(), b.GetName())
	})
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, l := range ls {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.GetName())
		b.WriteByte('=')
		b.WriteString(strconv.Quote(l.GetValue()))
	}
	b.WriteByte('}')
	return b.String()
}

func capBody(r io.Reader, max int64) ([]byte, error) {
	// Read one extra byte so an oversize body errors instead of silent truncation.
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func scrapeMetricURL(ctx context.Context, rawURL string) scrapeResult {
	ctx, cancel := context.WithTimeout(ctx, api.MetricSourceScrapeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return scrapeResult{Err: err}
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := scrapeHTTPClient.Do(req)
	if err != nil {
		return scrapeResult{Err: err}
	}
	defer resp.Body.Close()

	body, err := capBody(resp.Body, api.MetricSourceMaxBodyBytes)
	if err != nil {
		return scrapeResult{Err: err}
	}
	if resp.StatusCode != http.StatusOK {
		return scrapeResult{Err: fmt.Errorf("status %d", resp.StatusCode)}
	}
	return parsePromMetrics(body, api.MetricSourceMaxSeries)
}

func (w *Worker) syncCustomMetrics(ctx context.Context) {
	// ListMetricSources is a new RPC; an older apiserver fails here. Log and
	// skip so this collector can roll out before apiserver.
	res, err := w.Client.Collector().ListMetricSources(ctx, &api.CollectorListMetricSources{
		Location: w.Location,
	})
	if err != nil {
		slog.Error("collector: list metric sources error", "error", err)
		return
	}
	if res == nil || len(res.Items) == 0 {
		return
	}

	sem := semaphore.NewWeighted(customMetricsConcurrency)
	var wg sync.WaitGroup
	for _, item := range res.Items {
		if err := sem.Acquire(ctx, 1); err != nil {
			slog.Error("collector: custom metrics semaphore", "error", err)
			break
		}
		wg.Go(func() {
			defer sem.Release(1)
			w.scrapeMetricSource(ctx, item)
		})
	}
	wg.Wait()
}

func (w *Worker) scrapeMetricSource(ctx context.Context, item *api.CollectorMetricSource) {
	if item == nil || item.URL == "" {
		return
	}

	res := scrapeMetricURL(ctx, item.URL)
	if res.Err != nil {
		slog.Error("collector: scrape metric source error",
			"project", item.ProjectID, "source", item.SourceID, "name", item.Name, "error", res.Err)
		return
	}
	if len(res.Samples) == 0 {
		return
	}
	if res.Truncated {
		slog.Warn("collector: metric source truncated",
			"project", item.ProjectID, "source", item.SourceID, "name", item.Name, "series", len(res.Samples))
	}

	at := time.Now().Unix()
	req := api.CollectorSetCustomUsage{
		Location: w.Location,
		List:     make([]*api.CollectorCustomUsageItem, 0, len(res.Samples)),
	}
	for _, s := range res.Samples {
		req.List = append(req.List, &api.CollectorCustomUsageItem{
			ProjectID: item.ProjectID,
			SourceID:  item.SourceID,
			Series:    s.Series,
			Value:     s.Value,
			At:        at,
		})
	}
	if _, err := w.Client.Collector().SetCustomUsage(ctx, &req); err != nil {
		slog.Error("collector: set custom usage error",
			"project", item.ProjectID, "source", item.SourceID, "name", item.Name, "error", err)
	}
}
