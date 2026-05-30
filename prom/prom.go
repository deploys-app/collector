package prom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
		Status string
		Data   struct {
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
		return "", fmt.Errorf("status not success")
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

func (c *Client) GetEgress() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`rate(container_network_transmit_bytes_total{namespace="%s"}[1m])`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
}

func (c *Client) GetRequests() ([]*PodVector, error) {
	q := make(url.Values)

	q.Set("query", fmt.Sprintf(
		`sum(rate(parapet_requests{ingress_namespace="%s"}[1m])) by (service_name)`,
		c.Namespace,
	))

	return c.queryPodVectors(q)
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
