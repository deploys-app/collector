package main

import (
	"context"
	"fmt"
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

	// One-shot backfill mode: when BACKFILL_FROM is set, re-run project-usage
	// collection for [BACKFILL_FROM, BACKFILL_TO] (UTC YYYY-MM-DD, inclusive)
	// and exit without starting the periodic loops. Idempotent (SetProjectUsage
	// upserts), so safe to re-run. Used to recover the cache-egress outage.
	if from := config.String("backfill_from"); from != "" {
		runBackfill(&w, from, config.String("backfill_to"))
		return
	}

	stopSignal := make(chan os.Signal, 1)
	signal.Notify(stopSignal, syscall.SIGTERM)

	stop := make(chan struct{})
	go func() {
		<-stopSignal
		close(stop)
	}()

	var wg sync.WaitGroup

	wg.Go(func() {

		for {
			w.RunProject()

			select {
			case <-stop:
				return
			case <-time.After(30 * time.Minute):
			}
		}
	})

	wg.Go(func() {

		for {
			w.RunDeployment()

			select {
			case <-stop:
				return
			case <-time.After(1 * time.Minute):
			}
		}
	})

	wg.Wait()
}

// runBackfill parses the UTC date window and drives Worker.Backfill, exiting
// non-zero on any setup error so a misconfigured one-shot job fails loudly.
func runBackfill(w *Worker, fromStr, toStr string) {
	if toStr == "" {
		slog.Error("collector: backfill_to required when backfill_from is set")
		os.Exit(1)
	}
	from, err := time.ParseInLocation(time.DateOnly, fromStr, time.UTC)
	if err != nil {
		slog.Error("collector: invalid backfill_from", "value", fromStr, "error", err)
		os.Exit(1)
	}
	to, err := time.ParseInLocation(time.DateOnly, toStr, time.UTC)
	if err != nil {
		slog.Error("collector: invalid backfill_to", "value", toStr, "error", err)
		os.Exit(1)
	}
	if to.Before(from) {
		slog.Error("collector: backfill_to before backfill_from", "from", fromStr, "to", toStr)
		os.Exit(1)
	}

	slog.Info("collector: backfill start", "from", fromStr, "to", toStr, "location", w.Location)
	if err := w.Backfill(context.Background(), from, to); err != nil {
		slog.Error("collector: backfill error", "error", err)
		os.Exit(1)
	}
	slog.Info("collector: backfill done", "from", fromStr, "to", toStr)
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

		go func() {
			defer sem.Release(1)

			w.syncProjectUsage(ctx, p)
		}()
	}
}

func (w *Worker) RunDeployment() {
	ctx := context.Background()

	w.syncDeploymentUsage(ctx)
	w.syncStaticRequests(ctx)
}

// syncStaticRequests records per-site request rate for Static deployments,
// which have no pod/Service and so never appear in the container/parapet
// metrics syncDeploymentUsage reads. The shared static-gateway exposes a
// per-site counter labeled by project SID + site name; deployment_usages is
// keyed by numeric project id, so we resolve the SID via the location's
// project list and write the rows under the "requests" resource (keyed by the
// site's display name — deployment.metrics reads Static usage by display name).
func (w *Worker) syncStaticRequests(ctx context.Context) {
	vs, err := w.PromClient.GetStaticRequests()
	if err != nil {
		slog.Error("collector: get static requests error", "error", err)
		return
	}
	if len(vs) == 0 {
		return
	}

	l, err := w.Client.Collector().Location(ctx, &api.CollectorLocation{Location: w.Location})
	if err != nil {
		slog.Error("collector: get location data for static requests", "error", err)
		return
	}
	idBySID := make(map[string]int64, len(l.Projects))
	for _, p := range l.Projects {
		if p.SID != "" {
			idBySID[p.SID] = p.ID
		}
	}

	req := api.CollectorSetDeploymentUsage{
		Location: w.Location,
	}
	for _, v := range vs {
		projectID := idBySID[v.Project]
		if projectID == 0 {
			continue
		}

		f, _ := strconv.ParseFloat(v.Value, 64)

		req.List = append(req.List, &api.CollectorDeploymentUsageItem{
			ProjectID:      projectID,
			DeploymentName: v.Name,
			Name:           "requests",
			Pod:            v.Name,
			Value:          f,
			At:             v.Time,
		})
	}

	if len(req.List) == 0 {
		return
	}

	_, err = w.Client.Collector().SetDeploymentUsage(ctx, &req)
	if err != nil {
		slog.Error("collector: set static requests error", "error", err)
	}
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

// billingRangeSeconds is the number of seconds a day's averaged gauges
// (cpu/disk/replica) are scaled by to produce a per-day total — avg_over_time
// over the day, times this. It projects to a full day: for the in-progress
// current day `now` is before the day end `et`, so `et` is used (a full day,
// matching how the average is later multiplied). For a completed day, callers
// pass now == et so this stays exactly one day. Passing a real wall-clock `now`
// for an already-finished day would inflate this to multiple days and over-bill
// — which is why Backfill pins now to et.
func billingRangeSeconds(t, now, et time.Time) int64 {
	n := now
	if n.Before(et) {
		n = et
	}
	return int64(n.Sub(t) / time.Second)
}

// Backfill re-runs project-usage collection for every day in [from, to]
// (inclusive, UTC day boundaries). It exists to recover days the collector
// failed to write — e.g. the cache-egress query outage, where the first
// Prometheus error aborted syncProjectUsageDate before it wrote ANY project
// resource for domain-having projects. SetProjectUsage upserts on
// (project, location, date, name), so re-running is idempotent: unaffected
// projects/days are rewritten with identical values, never double-counted.
//
// Recoverability is bounded by Prometheus retention — days older than retention
// return no samples and cannot be reconstructed. Each completed day is billed
// for its full length: passing now = et pins billingRangeSeconds to one day.
func (w *Worker) Backfill(ctx context.Context, from, to time.Time) error {
	l, err := w.Client.Collector().Location(ctx, &api.CollectorLocation{Location: w.Location})
	if err != nil {
		return fmt.Errorf("get location data: %w", err)
	}

	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		et := d.AddDate(0, 0, 1)
		slog.Info("collector: backfill day", "date", d.Format(time.DateOnly), "projects", len(l.Projects))

		sem := semaphore.NewWeighted(10)
		var wg sync.WaitGroup
		for _, p := range l.Projects {
			if err := sem.Acquire(ctx, 1); err != nil {
				return err
			}
			wg.Go(func() {
				defer sem.Release(1)

				// now = et: this is a completed day, bill its full length.
				w.syncProjectUsageDate(ctx, p, d, et)
			})
		}
		wg.Wait()
	}
	return nil
}

func (w *Worker) syncProjectUsageDate(ctx context.Context, p *api.CollectorProject, t time.Time, now time.Time) {
	et := t.AddDate(0, 0, 1)
	days := "1d"

	rangeSeconds := billingRangeSeconds(t, now, et)

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
	wg.Go(func() {
		syncVector("cpu_usage", w.PromClient.GetCPUUsage)
	})

	wg.Go(func() {
		syncVector("cpu", w.PromClient.GetCPU)
	})

	wg.Go(func() {
		syncVector("cpu_limit", w.PromClient.GetCPULimit)
	})

	wg.Go(func() {
		syncVector("memory_usage", w.PromClient.GetMemoryUsage)
	})

	wg.Go(func() {
		syncVector("memory", w.PromClient.GetMemory)
	})

	wg.Go(func() {
		syncVector("memory_limit", w.PromClient.GetMemoryLimit)
	})

	wg.Go(func() {
		syncVector("egress", w.PromClient.GetEgress)
	})

	wg.Go(func() {
		syncVector("requests", w.PromClient.GetRequests)
	})

	wg.Go(func() {
		syncDiskVector("disk_usage", w.PromClient.GetDiskUsage)
	})

	wg.Go(func() {
		syncDiskVector("disk_size", w.PromClient.GetDiskSize)
	})

	wg.Go(func() {
		w.syncWAFUsage(ctx)
	})

	wg.Go(func() {
		w.syncRateLimitUsage(ctx)
	})

	wg.Go(func() {
		w.syncCacheOverrideUsage(ctx)
	})

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

// syncCacheOverrideUsage collects per-minute cache-override decision counts and
// upserts them — syncRateLimitUsage for parapet_cache_override_total. Same
// lookback / idempotent-upsert contract; project attribution comes from the
// project-prefixed override id embedded in the series name
// (zone:<ns>/<configmap>:<projectID>-<rand>). The bucket key carries both
// action and result (the cache vec has both labels).
func (w *Worker) syncCacheOverrideUsage(ctx context.Context) {
	slog.Info("collector: sync cache override")

	lookback := w.WAFLookback
	if lookback <= 0 {
		lookback = 15 * time.Minute
	}

	end := time.Now().Truncate(time.Minute).Unix()
	start := end - int64(lookback/time.Second)

	samples, err := w.PromClient.GetCacheOverrideDecisions(start, end)
	if err != nil {
		slog.Error("collector: sync cache override error", "error", err)
		return
	}

	req := api.CollectorSetCacheOverrideUsage{
		Location: w.Location,
	}
	for _, s := range samples {
		// A registered-but-idle override reports increase==0 every minute; skip so
		// the table stays sparse (absent bucket == zero).
		if s.Value == 0 {
			continue
		}

		// zone:<ns>/<configmap>:<overrideID> — the override id is everything after
		// the last ':'. Anything without one isn't a zone series; skip.
		i := strings.LastIndexByte(s.Name, ':')
		if i < 0 {
			continue
		}
		overrideID := s.Name[i+1:]

		m := reWAFRuleProject.FindStringSubmatch(overrideID)
		if m == nil {
			continue
		}
		projectID, _ := strconv.ParseInt(m[1], 10, 64)
		if projectID == 0 {
			continue
		}

		req.List = append(req.List, &api.CollectorCacheOverrideUsageItem{
			ProjectID:  projectID,
			OverrideID: overrideID,
			Action:     s.Action,
			Result:     s.Result,
			Value:      s.Value,
			At:         s.Ts,
		})
	}

	if len(req.List) == 0 {
		return
	}

	_, err = w.Client.Collector().SetCacheOverrideUsage(ctx, &req)
	if err != nil {
		slog.Error("collector: sync cache override error", "error", err)
		return
	}
}
