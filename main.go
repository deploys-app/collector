package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/acoshift/configfile"
	"github.com/deploys-app/api"
	"github.com/deploys-app/api/client"
	"golang.org/x/sync/semaphore"

	"github.com/deploys-app/collector/prom"
)

var config = configfile.NewEnvReader()

func main() {
	namespace := config.String("namespace")

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	token := config.String("token")
	if token == "" {
		slog.Error("token required")
		os.Exit(1)
	}

	w := Worker{
		PromClient: &prom.Client{
			Namespace: namespace,
			Endpoint:  config.MustString("prom_endpoint"),
		},
		Client: &client.Client{
			Endpoint:   config.String("api_endpoint"),
			HTTPClient: httpClient,
			Auth: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+token)
			},
		},
		Location: config.MustString("location"),
		// How far back each WAF sync re-queries. Larger = recovers longer collector
		// outages (bounded by Prometheus retention); buckets are upserted so the
		// overlap with the previous run is harmless.
		WAFLookback: config.DurationDefault("waf_lookback", 15*time.Minute),
	}

	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGTERM)

	stop := make(chan struct{})
	go func() {
		<-stopSignal
		close(stop)
	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			w.RunProject()

			select {
			case <-stop:
				return
			case <-time.After(30 * time.Minute):
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			w.RunDeployment()

			select {
			case <-stop:
				return
			case <-time.After(1 * time.Minute):
			}
		}
	}()

	wg.Wait()
}

type Worker struct {
	PromClient  *prom.Client
	Location    string
	Client      api.Interface
	WAFLookback time.Duration
}

func (w *Worker) RunProject() {
	ctx := context.Background()

	l, err := w.Client.Collector().Location(ctx, &api.CollectorLocation{Location: w.Location})
	if err != nil {
		slog.Error("collector: get location data", "error", err)
		return
	}

	sem := semaphore.NewWeighted(10)
	for _, p := range l.Projects {
		err := sem.Acquire(ctx, 1)
		if err != nil {
			return
		}

		p := p
		go func() {
			defer sem.Release(1)

			w.syncProjectUsage(ctx, p)
		}()
	}
}

func (w *Worker) RunDeployment() {
	ctx := context.Background()

	w.syncDeploymentUsage(ctx)
}

func (w *Worker) syncProjectUsage(ctx context.Context, p *api.CollectorProject) {
	slog.Info("collector: sync project", "project", p.ID)

	now := time.Now()
	t := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// calculate yesterday, if time < 5am
	if now.Hour() <= 5 {
		yesterday := t.AddDate(0, 0, -1)
		w.syncProjectUsageDate(ctx, p, yesterday, now)
	}

	// calculate today
	w.syncProjectUsageDate(ctx, p, t, now)
}

func (w *Worker) syncProjectUsageDate(ctx context.Context, p *api.CollectorProject, t time.Time, now time.Time) {
	et := t.AddDate(0, 0, 1)
	days := "1d"

	n := now
	if n.Before(et) {
		n = et
	}
	rangeSeconds := int64(n.Sub(t) / time.Second)

	req := api.CollectorSetProjectUsage{
		Location:  w.Location,
		ProjectID: p.ID,
		At:        t.Format(time.RFC3339),
	}

	// cpu usage
	value, err := w.PromClient.SummaryCPUUsage(p.ID, et.Unix(), days, rangeSeconds)
	if err != nil {
		slog.Error("collector: get prom summary cpu usage error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "cpu_usage", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "cpu_usage",
		Value: value,
	})

	// cpu
	value, err = w.PromClient.SummaryCPU(p.ID, et.Unix(), days, rangeSeconds)
	if err != nil {
		slog.Error("collector: get prom summary cpu error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "cpu", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "cpu",
		Value: value,
	})

	// memory
	value, err = w.PromClient.SummaryMemory(p.ID, et.Unix(), days, rangeSeconds)
	if err != nil {
		slog.Error("collector: get prom summary memory error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "memory", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "memory",
		Value: value,
	})

	// egress
	value, err = w.PromClient.SummaryEgress(p.ID, et.Unix(), days)
	if err != nil {
		slog.Error("collector: get prom summary egress error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "egress", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "egress",
		Value: value,
	})

	// waf egress (external HTTP routes — edge-measured, since they have no pod
	// for the pod-based SummaryEgress above to see)
	value, err = w.PromClient.SummaryWAFEgress(p.ID, et.Unix(), days)
	if err != nil {
		slog.Error("collector: get prom summary waf egress error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "waf_egress", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "waf_egress",
		Value: value,
	})

	// cache egress (bytes served directly from the edge cache — HITs are
	// origin-invisible so no existing metric bills them; MISS bytes travel to the
	// origin and are already counted in egress / waf_egress)
	if len(p.Domains) == 0 {
		// No domains routed to this project; skip the Prometheus query and report
		// zero so any stale value is reset on the apiserver side.
		req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
			Name:  "cache_egress",
			Value: "0",
		})
	} else {
		value, err = w.PromClient.SummaryCacheEgress(p.Domains, et.Unix(), days)
		if err != nil {
			slog.Error("collector: get prom summary cache egress error", "error", err)
			return
		}
		slog.Info("collector: syncProjectUsageDate", "resource", "cache_egress", "project", p.ID, "value", value)
		req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
			Name:  "cache_egress",
			Value: value,
		})
	}

	// disk
	value, err = w.PromClient.SummaryDisk(p.ID, et.Unix(), days, rangeSeconds)
	if err != nil {
		slog.Error("collector: get prom summary disk error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "disk", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "disk",
		Value: value,
	})

	// replica
	value, err = w.PromClient.SummaryReplica(p.ID, et.Unix(), days, rangeSeconds)
	if err != nil {
		slog.Error("collector: get prom summary replica error", "error", err)
		return
	}
	slog.Info("collector: syncProjectUsageDate", "resource", "replica", "project", p.ID, "value", value)
	req.Resources = append(req.Resources, &api.CollectorProjectUsageResource{
		Name:  "replica",
		Value: value,
	})

	if len(req.Resources) == 0 {
		return
	}

	_, err = w.Client.Collector().SetProjectUsage(ctx, &req)
	if err != nil {
		slog.Error("collector: set project usage error", "error", err)
		return
	}
}

var (
	rePodNameProject     = regexp.MustCompile(`^(.+)-(\d+)-[^-]+-[^-]+$`)
	reServiceNameProject = regexp.MustCompile(`^(.+)-(\d+)$`)
	reVolumeNameProject  = regexp.MustCompile(`^(.+)-(\d+)$`)
	// WAF rule ids are server-generated as <projectID>-<rand>; the leading
	// numeric run is the owning project (parapet_waf_matches carries no project
	// label, so this prefix is the only attribution signal).
	reWAFRuleProject = regexp.MustCompile(`^(\d+)-`)
)

func (w *Worker) syncDeploymentUsage(ctx context.Context) {
	syncVector := func(name string, f func() ([]*prom.PodVector, error)) error {
		slog.Info("collector: sync deployment", "name", name)

		vs, err := f()
		if err != nil {
			slog.Error("collector: sync deployment error", "name", name, "error", err)
			return err
		}

		req := api.CollectorSetDeploymentUsage{
			Location: w.Location,
		}

		for _, v := range vs {
			at := v.Time

			var (
				ns  [][]string
				pod string
			)
			if v.Pod != "" {
				pod = v.Pod
				ns = rePodNameProject.FindAllStringSubmatch(pod, -1)
			} else if v.Service != "" {
				pod = v.Service
				ns = reServiceNameProject.FindAllStringSubmatch(pod, -1)
			}
			if len(ns) != 1 || len(ns[0]) != 3 {
				continue
			}
			projectID, _ := strconv.ParseInt(ns[0][2], 10, 64)
			if projectID == 0 {
				continue
			}

			f, _ := strconv.ParseFloat(v.Value, 64)

			req.List = append(req.List, &api.CollectorDeploymentUsageItem{
				ProjectID:      projectID,
				DeploymentName: ns[0][1],
				Name:           name,
				Pod:            pod,
				Value:          f,
				At:             at,
			})
		}

		if len(req.List) == 0 {
			return nil
		}

		_, err = w.Client.Collector().SetDeploymentUsage(ctx, &req)
		if err != nil {
			slog.Error("collector: sync deployment error", "name", name, "error", err)
			return err
		}
		return nil
	}

	syncDiskVector := func(name string, f func() ([]*prom.VolumeVector, error)) error {
		slog.Info("collector: sync disk", "name", name)

		vs, err := f()
		if err != nil {
			slog.Error("collector: sync disk error", "name", name, "error", err)
			return err
		}

		req := api.CollectorSetDiskUsage{
			Location: w.Location,
		}

		for _, v := range vs {
			at := v.Time

			var (
				ns [][]string
			)
			ns = reVolumeNameProject.FindAllStringSubmatch(v.Volume, -1)
			if len(ns) != 1 || len(ns[0]) != 3 {
				continue
			}
			projectID, _ := strconv.ParseInt(ns[0][2], 10, 64)
			if projectID == 0 {
				continue
			}

			f, _ := strconv.ParseFloat(v.Value, 64)

			req.List = append(req.List, &api.CollectorDiskUsageItem{
				ProjectID: projectID,
				DiskName:  ns[0][1],
				Name:      name,
				Value:     f,
				At:        at,
			})
		}

		if len(req.List) == 0 {
			return nil
		}

		_, err = w.Client.Collector().SetDiskUsage(ctx, &req)
		if err != nil {
			slog.Error("collector: sync disk error", "name", name, "error", err)
			return err
		}
		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("cpu_usage", w.PromClient.GetCPUUsage)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("cpu", w.PromClient.GetCPU)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("cpu_limit", w.PromClient.GetCPULimit)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("memory_usage", w.PromClient.GetMemoryUsage)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("memory", w.PromClient.GetMemory)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("memory_limit", w.PromClient.GetMemoryLimit)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("egress", w.PromClient.GetEgress)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncVector("requests", w.PromClient.GetRequests)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncDiskVector("disk_usage", w.PromClient.GetDiskUsage)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		syncDiskVector("disk_size", w.PromClient.GetDiskSize)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.syncWAFUsage(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		w.syncRateLimitUsage(ctx)
	}()

	wg.Wait()
}

// syncWAFUsage collects per-minute WAF match counts and upserts them. It
// re-queries a lookback window each run (not just the last minute) so a collector
// outage shorter than the window is back-filled from Prometheus; the apiserver
// upserts by bucket key, so the overlap is idempotent.
func (w *Worker) syncWAFUsage(ctx context.Context) {
	slog.Info("collector: sync waf")

	lookback := w.WAFLookback
	if lookback <= 0 {
		lookback = 15 * time.Minute
	}

	// Align to the minute so every run targets the same bucket timestamps —
	// required for the upsert to overwrite rather than duplicate.
	end := time.Now().Truncate(time.Minute).Unix()
	start := end - int64(lookback/time.Second)

	samples, err := w.PromClient.GetWAFMatches(start, end)
	if err != nil {
		slog.Error("collector: sync waf error", "error", err)
		return
	}

	req := api.CollectorSetWAFUsage{
		Location: w.Location,
	}
	for _, s := range samples {
		// A registered-but-idle rule reports increase==0 every minute; skip those
		// so the table stays sparse (an absent bucket already means zero for both
		// the chart and the range-sum).
		if s.Value == 0 {
			continue
		}

		m := reWAFRuleProject.FindStringSubmatch(s.RuleID)
		if m == nil {
			continue
		}
		projectID, _ := strconv.ParseInt(m[1], 10, 64)
		if projectID == 0 {
			continue
		}

		req.List = append(req.List, &api.CollectorWAFUsageItem{
			ProjectID: projectID,
			RuleID:    s.RuleID,
			Action:    s.Action,
			Value:     s.Value,
			At:        s.Ts,
		})
	}

	if len(req.List) == 0 {
		return
	}

	_, err = w.Client.Collector().SetWAFUsage(ctx, &req)
	if err != nil {
		slog.Error("collector: sync waf error", "error", err)
		return
	}
}

// syncRateLimitUsage collects per-minute zone rate-limit decision counts and
// upserts them — syncWAFUsage for parapet_ratelimit_total. Same lookback /
// idempotent-upsert contract; project attribution comes from the
// project-prefixed limit id embedded in the series name
// (zone:<ns>/<configmap>:<projectID>-<rand>).
func (w *Worker) syncRateLimitUsage(ctx context.Context) {
	slog.Info("collector: sync ratelimit")

	lookback := w.WAFLookback
	if lookback <= 0 {
		lookback = 15 * time.Minute
	}

	end := time.Now().Truncate(time.Minute).Unix()
	start := end - int64(lookback/time.Second)

	samples, err := w.PromClient.GetRateLimitDecisions(start, end)
	if err != nil {
		slog.Error("collector: sync ratelimit error", "error", err)
		return
	}

	req := api.CollectorSetRateLimitUsage{
		Location: w.Location,
	}
	for _, s := range samples {
		// A registered-but-idle limit reports increase==0 every minute; skip so
		// the table stays sparse (absent bucket == zero).
		if s.Value == 0 {
			continue
		}

		// zone:<ns>/<configmap>:<limitID> — the limit id is everything after the
		// last ':'. Anything without one isn't a zone series; skip.
		i := strings.LastIndexByte(s.Name, ':')
		if i < 0 {
			continue
		}
		limitID := s.Name[i+1:]

		m := reWAFRuleProject.FindStringSubmatch(limitID)
		if m == nil {
			continue
		}
		projectID, _ := strconv.ParseInt(m[1], 10, 64)
		if projectID == 0 {
			continue
		}

		req.List = append(req.List, &api.CollectorRateLimitUsageItem{
			ProjectID: projectID,
			LimitID:   limitID,
			Result:    s.Result,
			Value:     s.Value,
			At:        s.Ts,
		})
	}

	if len(req.List) == 0 {
		return
	}

	_, err = w.Client.Collector().SetRateLimitUsage(ctx, &req)
	if err != nil {
		slog.Error("collector: sync ratelimit error", "error", err)
		return
	}
}
