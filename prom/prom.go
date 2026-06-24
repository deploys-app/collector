package prom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type Client struct {
	Endpoint   string
	Namespace  string
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) do(path string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.Endpoint+path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c *Client) queryVectorValue(q url.Values) (string, error) {
	resp, err := c.do("/api/v1/query?" + q.Encode())
	if err != nil {
		return "", err
	}
	var p struct {
		Status    string
		ErrorType string
		Error     string
		Data      struct {
			ResultType string
			Result     []struct {
				Value []any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return "", err
	}

	if p.Status != "success" {
		// Surface Prometheus's own errorType/error so a malformed query (e.g. a
		// bad regex escape) is diagnosable from the log instead of opaque.
		return "", fmt.Errorf("prometheus status %q (%s): %s", p.Status, p.ErrorType, p.Error)
	}

	if len(p.Data.Result) != 1 {
		return "", fmt.Errorf("result data length not equal to 1")
	}

	if len(p.Data.Result[0].Value) != 2 {
		return "", fmt.Errorf("result data at index 0 value length not equal to 2")
	}

	s, ok := p.Data.Result[0].Value[1].(string)
	if !ok {
		return "", fmt.Errorf("can not cast result data to string")
	}
	return s, nil
}

type PodVector struct {
	Pod     string
	Service string
	Time    int64
	Value   string
}

func (c *Client) queryPodVectors(q url.Values) ([]*PodVector, error) {
	resp, err := c.do("/api/v1/query?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Value  []any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	rs := p.Data.Result

	vs := make([]*PodVector, 0, len(rs))
	for _, x := range rs {
		pod := x.Metric["pod"]
		service := x.Metric["service_name"]
		if len(x.Value) != 2 {
			continue
		}
		if pod == "" && service == "" {
			continue
		}

		vs = append(vs, &PodVector{
			Pod:     pod,
			Service: service,
			Time:    int64(x.Value[0].(float64)),
			Value:   x.Value[1].(string),
		})
	}

	return vs, nil
}

type VolumeVector struct {
	Volume string
	Time   int64
	Value  string
}

func (c *Client) queryVolumeVectors(q url.Values) ([]*VolumeVector, error) {
	resp, err := c.do("/api/v1/query?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Value  []any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	rs := p.Data.Result

	vs := make([]*VolumeVector, 0, len(rs))
	for _, x := range rs {
		volume := x.Metric["persistentvolumeclaim"]
		if len(x.Value) != 2 {
			continue
		}
		if volume == "" {
			continue
		}

		vs = append(vs, &VolumeVector{
			Volume: volume,
			Time:   int64(x.Value[0].(float64)),
			Value:  x.Value[1].(string),
		})
	}

	return vs, nil
}

func (c *Client) queryMatrixValue(q url.Values) ([][]string, error) {
	resp, err := c.do("/api/v1/query_range?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []struct {
				Values [][]any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	if len(p.Data.Result) != 1 {
		return nil, fmt.Errorf("not ok")
	}

	var res [][]string
	for _, vv := range p.Data.Result[0].Values {
		if len(vv) != 2 {
			continue
		}
		t, ok := vv[0].(float64)
		if !ok {
			continue
		}
		v, ok := vv[1].(string)
		if !ok {
			continue
		}

		res = append(res, []string{
			strconv.FormatFloat(t, 'f', 3, 64),
			v,
		})
	}

	return res, nil
}

type WAFSample struct {
	RuleID string
	Action string
	Ts     int64   // unix second, minute-aligned bucket
	Value  float64 // matches in that minute
}

// queryWAFMatrix runs a range query and flattens every series' samples into
// WAFSamples, keeping the rule_id / action labels. Unlike queryMatrixValue it
// allows many series (one per (rule_id, action)).
func (c *Client) queryWAFMatrix(q url.Values) ([]*WAFSample, error) {
	resp, err := c.do("/api/v1/query_range?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Values [][]any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	var vs []*WAFSample
	for _, r := range p.Data.Result {
		ruleID := r.Metric["rule_id"]
		action := r.Metric["action"]
		if ruleID == "" {
			continue
		}
		for _, vv := range r.Values {
			if len(vv) != 2 {
				continue
			}
			ts, ok := vv[0].(float64)
			if !ok {
				continue
			}
			s, ok := vv[1].(string)
			if !ok {
				continue
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
			vs = append(vs, &WAFSample{
				RuleID: ruleID,
				Action: action,
				Ts:     int64(ts),
				Value:  f,
			})
		}
	}

	return vs, nil
}

type RateLimitSample struct {
	Name   string // series name: zone:<namespace>/<configmap>:<limitID>
	Result string // allowed|limited
	Ts     int64  // unix second, minute-aligned bucket
	Value  float64
}

// queryRateLimitMatrix runs a range query and flattens every series' samples
// into RateLimitSamples, keeping the name / result labels — queryWAFMatrix for
// parapet_ratelimit_total's label set.
func (c *Client) queryRateLimitMatrix(q url.Values) ([]*RateLimitSample, error) {
	resp, err := c.do("/api/v1/query_range?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Values [][]any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	var vs []*RateLimitSample
	for _, r := range p.Data.Result {
		name := r.Metric["name"]
		result := r.Metric["result"]
		if name == "" {
			continue
		}
		for _, vv := range r.Values {
			if len(vv) != 2 {
				continue
			}
			ts, ok := vv[0].(float64)
			if !ok {
				continue
			}
			s, ok := vv[1].(string)
			if !ok {
				continue
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
			vs = append(vs, &RateLimitSample{
				Name:   name,
				Result: result,
				Ts:     int64(ts),
				Value:  f,
			})
		}
	}

	return vs, nil
}

// GetRateLimitDecisions pulls per-minute zone rate-limit decision counts over
// [startUnix, endUnix] at a 60s step — GetWAFMatches for
// parapet_ratelimit_total. The name=~"zone:.+" matcher excludes the
// platform-owned global set (named "global:<id>", which carries no project
// prefix to attribute); zone series are named zone:<ns>/<configmap>:<limitID>.
func (c *Client) GetRateLimitDecisions(startUnix, endUnix int64) ([]*RateLimitSample, error) {
	q := make(url.Values)
	q.Set("query", `sum(increase(parapet_ratelimit_total{name=~"zone:.+"}[1m])) by (name, result)`)
	q.Set("start", strconv.FormatInt(startUnix, 10))
	q.Set("end", strconv.FormatInt(endUnix, 10))
	q.Set("step", "60")

	return c.queryRateLimitMatrix(q)
}

type CacheOverrideSample struct {
	Name   string // series name: zone:<namespace>/<configmap>:<overrideID>
	Action string // cache|bypass
	Result string // applied|shadow|error
	Ts     int64  // unix second, minute-aligned bucket
	Value  float64
}

// queryCacheOverrideMatrix runs a range query and flattens every series'
// samples into CacheOverrideSamples, keeping the name / action / result labels —
// queryRateLimitMatrix for parapet_cache_override_total's label set.
func (c *Client) queryCacheOverrideMatrix(q url.Values) ([]*CacheOverrideSample, error) {
	resp, err := c.do("/api/v1/query_range?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Values [][]any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	var vs []*CacheOverrideSample
	for _, r := range p.Data.Result {
		name := r.Metric["name"]
		action := r.Metric["action"]
		result := r.Metric["result"]
		if name == "" {
			continue
		}
		for _, vv := range r.Values {
			if len(vv) != 2 {
				continue
			}
			ts, ok := vv[0].(float64)
			if !ok {
				continue
			}
			s, ok := vv[1].(string)
			if !ok {
				continue
			}
			f, err := strconv.ParseFloat(s, 64)
			if err != nil {
				continue
			}
			vs = append(vs, &CacheOverrideSample{
				Name:   name,
				Action: action,
				Result: result,
				Ts:     int64(ts),
				Value:  f,
			})
		}
	}

	return vs, nil
}

// GetCacheOverrideDecisions pulls per-minute cache-override decision counts over
// [startUnix, endUnix] at a 60s step — GetRateLimitDecisions for
// parapet_cache_override_total. The name=~"zone:.+" matcher excludes the
// platform-owned global set (named "global:<id>", which carries no project
// prefix to attribute); zone series are named zone:<ns>/<configmap>:<overrideID>.
func (c *Client) GetCacheOverrideDecisions(startUnix, endUnix int64) ([]*CacheOverrideSample, error) {
	q := make(url.Values)
	q.Set("query", `sum(increase(parapet_cache_override_total{name=~"zone:.+"}[1m])) by (name, action, result)`)
	q.Set("start", strconv.FormatInt(startUnix, 10))
	q.Set("end", strconv.FormatInt(endUnix, 10))
	q.Set("step", "60")

	return c.queryCacheOverrideMatrix(q)
}

// GetWAFMatches pulls per-minute WAF match counts over [startUnix, endUnix] at a
// 60s step. increase[1m] at a 60s step tiles the window with no gaps/overlaps,
// so summing buckets yields total hits. scope="zone" excludes the platform-owned
// global baseline (which carries no project prefix to attribute). The metric has
// no namespace label; each location's Prometheus scrapes only its own controller.
func (c *Client) GetWAFMatches(startUnix, endUnix int64) ([]*WAFSample, error) {
	q := make(url.Values)
	q.Set("query", `sum(increase(parapet_waf_matches{scope="zone"}[1m])) by (rule_id, action)`)
	q.Set("start", strconv.FormatInt(startUnix, 10))
	q.Set("end", strconv.FormatInt(endUnix, 10))
	q.Set("step", "60")

	return c.queryWAFMatrix(q)
}

func (c *Client) SummaryCPUUsage(projectID int64, startTimeUnix int64, dataRange string, rangeSecond int64) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		// `
		// 	clamp_min(
		// 		sum(increase(container_cpu_usage_seconds_total{name="",namespace="%s",pod=~".*-%d-[^-]+-[^-]+$"}[%s]))
		// 		- (sum(kube_pod_container_resource_requests{namespace="%s",resource="cpu",pod=~".*-%d-[^-]+-[^-]+$"}) * %d)
		// 	, 0) or vector(0)`,
		`sum(increase(container_cpu_usage_seconds_total{namespace="%s",name="",pod=~".*-%d-[^-]+-[^-]+$"}[%s])) or vector(0)`,
		// c.Namespace, projectID, dataRange,
		// c.Namespace, projectID, rangeSecond,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryCPU(projectID int64, startTimeUnix int64, dataRange string, rangeSecond int64) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(sum(avg_over_time(kube_pod_container_resource_requests{namespace="%s",resource="cpu",pod=~".*-%d-[^-]+-[^-]+$"}[%s])) or vector(0)) * %d`,
		c.Namespace, projectID, dataRange, rangeSecond,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryMemory(projectID int64, startTimeUnix int64, dataRange string, rangeSecond int64) (string, error) {
	q := make(url.Values)

	// 15 = scrape_interval
	q.Set("query", fmt.Sprintf(
		`(sum(sum_over_time(kube_pod_container_resource_requests{namespace="%s",resource="memory",pod=~".*-%d-[^-]+-[^-]+$"}[%s])) or vector(0)) * 15`,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryEgress(projectID int64, startTimeUnix int64, dataRange string) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(
			  sum(max_over_time(container_network_transmit_bytes_total{namespace="%[1]s",pod=~".*-%[2]d-[^-]+-[^-]+$"}[%[3]s]))
			  -
			  sum(min_over_time(container_network_transmit_bytes_total{namespace="%[1]s",pod=~".*-%[2]d-[^-]+-[^-]+$"}[%[3]s]))
		 ) or vector(0)`,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

// SummaryWAFEgress returns the bytes served from the edge to clients for a
// project's external HTTP routes over the day. External-route backends are
// Services named ext-<routeID>-<projectID>; parapet_backend_network_read_bytes
// is the response volume parapet reads back from the customer origin (≈ what is
// then served out to the client), and the service_name suffix attributes it to
// the project. This is the edge-measured counterpart to SummaryEgress, which is
// pod-based and therefore reports nothing for external routes (they have no pod).
func (c *Client) SummaryWAFEgress(projectID int64, startTimeUnix int64, dataRange string) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(
				  sum(max_over_time(parapet_backend_network_read_bytes{service_namespace="%[1]s",service_name=~"ext-.*-%[2]d"}[%[3]s]))
				  -
				  sum(min_over_time(parapet_backend_network_read_bytes{service_namespace="%[1]s",service_name=~"ext-.*-%[2]d"}[%[3]s]))
				) or vector(0)`,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

// SummaryStaticEgress returns the origin body bytes the shared static-gateway
// streamed for a project's Static deployments over the day. Static deployments
// have no pod, so SummaryEgress (pod-based) reports nothing for them; the gateway
// instead exports static_gateway_response_bytes_total labeled by project SID +
// site name, and this sums increase(...[1d]) across every site (name) and gateway
// replica for the project.
//
// increase() — not the max_over_time-min_over_time idiom of SummaryEgress — is
// used for the same reason as SummaryCacheEgress: the counter is exported by
// multiple gateway replicas independently, so a reset on one replica's restart
// would corrupt a cross-instance max-min difference; increase() handles per-series
// resets before the sum. projectSID is a validated id (api.ReValidSID:
// ^[a-z][a-z0-9-]*[^-]$ — no quotes or regex metacharacters), so it is safe to
// embed as an exact-match label.
func (c *Client) SummaryStaticEgress(projectSID string, startTimeUnix int64, dataRange string) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`sum(increase(static_gateway_response_bytes_total{project="%s"}[%s])) or vector(0)`,
		projectSID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryDisk(projectID int64, startTimeUnix int64, dataRange string, rangeSecond int64) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(sum(avg_over_time(kube_persistentvolumeclaim_resource_requests_storage_bytes{namespace="%s",persistentvolumeclaim=~".*-%d$"}[%s])) or vector(0)) * %d`,
		c.Namespace, projectID, dataRange, rangeSecond,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryEgressProcessing(projectID int64, startTimeUnix int64, dataRange string) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(
				  sum(max_over_time(parapet_backend_network_read_bytes{service_namespace="%s",service_name=~".*-%d$"}[%s]))
				  -
				  sum(min_over_time(parapet_backend_network_read_bytes{service_namespace="%s",service_name=~".*-%d$"}[%s]))
				) or vector(0)`,
		c.Namespace, projectID, dataRange,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryIngressProcessing(projectID int64, startTimeUnix int64, dataRange string) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(
		  sum(max_over_time(parapet_backend_network_write_bytes{service_namespace="%s",service_name=~".*-%d$"}[%s]))
		  -
		  sum(min_over_time(parapet_backend_network_write_bytes{service_namespace="%s",service_name=~".*-%d$"}[%s]))
		) or vector(0)`,
		c.Namespace, projectID, dataRange,
		c.Namespace, projectID, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) SummaryReplica(projectID int64, startTimeUnix int64, dataRange string, rangeSecond int64) (string, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`(sum(avg_over_time(kube_deployment_status_replicas_available{namespace="%s",deployment=~".*-%d$"}[%s])) or vector(0)) * %d`,
		c.Namespace, projectID, dataRange, rangeSecond,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}

func (c *Client) GetCPUUsage() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`irate(container_cpu_usage_seconds_total{namespace="%s",name=""}[1m])`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetCPU() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kube_pod_container_resource_requests{namespace="%s",resource="cpu"}`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetCPULimit() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kube_pod_container_resource_limits{namespace="%s",resource="cpu"} > 0`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetMemoryUsage() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`container_memory_usage_bytes{namespace="%s",name=""}`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetMemory() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kube_pod_container_resource_requests{namespace="%s",resource="memory"} > 0`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetMemoryLimit() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kube_pod_container_resource_limits{namespace="%s",resource="memory"} > 0`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

// GetEgress samples each pod's transmit bytes over the last minute. increase()
// (not rate()) makes the value a per-minute byte total: the deployment loop runs
// every minute, so consecutive [1m] samples tile the timeline and the apiserver
// sums them per bucket to chart total bytes transferred — the same per-minute
// count contract the WAF/ratelimit/cache syncs use. (Was rate() = bytes/sec.)
func (c *Client) GetEgress() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`increase(container_network_transmit_bytes_total{namespace="%s"}[1m])`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

// GetRequests sums each service's request count over the last minute. increase()
// (not rate()) makes the value a per-minute request total so the apiserver can
// sum buckets into total requests served; see GetEgress for the tiling contract.
// (Was rate() = requests/sec.)
func (c *Client) GetRequests() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`sum(increase(parapet_requests{ingress_namespace="%s"}[1m])) by (service_name)`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

// StaticRequestVector is one (project SID, site name) per-minute request-count
// sample from the shared static-gateway. Static deployments have no pod/Service,
// so their request volume is attributed by the gateway's own per-site labels
// instead of the pod/service_name labels the container metrics use.
type StaticRequestVector struct {
	Project string // project SID (e.g. "acme")
	Name    string // site / deployment display name
	Time    int64
	Value   string
}

func (c *Client) queryStaticRequestVectors(q url.Values) ([]*StaticRequestVector, error) {
	resp, err := c.do("/api/v1/query?" + q.Encode())
	if err != nil {
		return nil, err
	}
	var p struct {
		Status string
		Data   struct {
			ResultType string
			Result     []*struct {
				Metric map[string]string
				Value  []any
			}
		}
	}
	err = json.Unmarshal(resp, &p)
	if err != nil {
		return nil, err
	}

	if p.Status != "success" {
		return nil, fmt.Errorf("not ok")
	}

	vs := make([]*StaticRequestVector, 0, len(p.Data.Result))
	for _, x := range p.Data.Result {
		project := x.Metric["project"]
		name := x.Metric["name"]
		if len(x.Value) != 2 {
			continue
		}
		if project == "" || name == "" {
			continue
		}

		vs = append(vs, &StaticRequestVector{
			Project: project,
			Name:    name,
			Time:    int64(x.Value[0].(float64)),
			Value:   x.Value[1].(string),
		})
	}

	return vs, nil
}

// GetStaticRequests returns the per-site request count over the last minute
// served by the shared static-gateway, summed across gateway replicas and
// grouped by the project SID + site name the gateway labels each request with.
// increase() (not rate()) keeps these per-minute counts consistent with the
// pod-backed GetRequests, since both land in the same "requests" chart series.
func (c *Client) GetStaticRequests() ([]*StaticRequestVector, error) {
	q := make(url.Values)

	q.Set("query", `sum(increase(static_gateway_requests_total[1m])) by (project, name)`)

	return c.queryStaticRequestVectors(q)
}

func (c *Client) GetDiskUsage() ([]*VolumeVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kubelet_volume_stats_used_bytes{namespace="%s"}`,
		c.Namespace,
	))

	return c.queryVolumeVectors(q)
}

func (c *Client) GetDiskSize() ([]*VolumeVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`kubelet_volume_stats_capacity_bytes{namespace="%s"}`,
		c.Namespace,
	))

	return c.queryVolumeVectors(q)
}

// hostPattern builds a PromQL host label regex from a list of domain names.
// Plain domains have their dots escaped. PromQL label regexes are fully
// anchored by the engine, so no ^$ is needed.
//
// Wildcard domains (*.example.com) are deliberately skipped. The edge host
// label oracle (parapet-ingress-controller's IsKnownHost) is an exact
// string-map of Ingress-declared hosts: a wildcard Ingress route registers
// the literal "*.example.com", so real subdomain requests (foo.example.com)
// collapse to the "other" label and can never be attributed back to the
// wildcard project. Expanding *.example.com to a [^.]+\.example\.com regex
// would only capture concrete domains (e.g. x.example.com) that belong to a
// different project whose exact Ingress route happens to fall under the
// wildcard parent — causing cross-project double billing. Wildcard-domain
// cache egress is therefore deliberately unbilled until the edge oracle
// understands wildcard host matching.
func hostPattern(domains []string) string {
	parts := make([]string, 0, len(domains))
	for _, d := range domains {
		if strings.HasPrefix(d, "*.") {
			// Skip — see doc comment above.
			continue
		}
		parts = append(parts, regexp.QuoteMeta(d))
	}
	return strings.Join(parts, "|")
}

// SummaryCacheEgress returns the bytes served from the edge cache (HIT+STALE)
// for a project's domains over the day window ending at startTimeUnix.
//
// We use increase() rather than the max_over_time-min_over_time idiom used by
// SummaryEgress/SummaryWAFEgress: the cache metric is exported by multiple
// edge instances independently, and counter resets on eviction or restart would
// corrupt the max-min difference across instances that didn't all restart at the
// same time.
//
// Only HIT and STALE results are counted: MISS bytes flow through to the
// customer origin and are already accounted for as pod egress or waf_egress.
//
// Wildcard domains are stripped by hostPattern (see its doc comment for the
// reason). If stripping leaves no attributable domains, "0" is returned
// directly — querying with an empty pattern would match nothing anyway, and
// returning "0" ensures any stale value is reset on the apiserver side,
// consistent with the no-domains short-circuit in the caller.
func (c *Client) SummaryCacheEgress(domains []string, startTimeUnix int64, dataRange string) (string, error) {
	pattern := hostPattern(domains)
	if pattern == "" {
		// No exact-match domains after wildcard filtering; nothing attributable.
		return "0", nil
	}

	// hostPattern escapes regex metacharacters via regexp.QuoteMeta, so the
	// pattern carries backslashes (e.g. `example\.com`). It is embedded into a
	// PromQL double-quoted string literal, which processes Go-style escapes — a
	// bare `\.` is an invalid escape sequence and Prometheus rejects the whole
	// query (surfacing as "status not success"). Double the backslashes so the
	// literal decodes back to the intended regex. (Domains can't contain `"`, so
	// backslash is the only character needing this.)
	pattern = strings.ReplaceAll(pattern, `\`, `\\`)

	q := make(url.Values)
	q.Set("query", fmt.Sprintf(
		`sum(increase(parapet_cache_egress_bytes{result=~"HIT|STALE",host=~"%s"}[%s])) or vector(0)`,
		pattern, dataRange,
	))
	q.Set("time", strconv.FormatInt(startTimeUnix, 10))

	return c.queryVectorValue(q)
}
