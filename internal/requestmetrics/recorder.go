// Package requestmetrics counts each project's auth requests, errors and
// latency for Studio's request charts (EXC-656). The series live in their own
// registry, served only on the internal listener provisioning scrapes, so the
// public /metrics never carries a per-project label.
package requestmetrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// latencyBuckets match the engine's, so provisioning can merge them across services.
var latencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

const family = "auth"

// Recorder holds the per-project series of one process.
type Recorder struct {
	registry    *prometheus.Registry
	requests    *prometheus.HistogramVec
	dropped     prometheus.Counter
	serves      func(projectID string) bool
	maxProjects int

	mu       sync.Mutex
	admitted map[string]bool
}

// NewRecorder records only projects serves vouches for, and at most
// maxProjects of them, so random paths cannot grow the series.
func NewRecorder(serves func(projectID string) bool, maxProjects int) *Recorder {
	registry := prometheus.NewRegistry()
	recorder := &Recorder{
		registry: registry,
		requests: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "excalibase_requests_seconds",
			Help:    "Requests per project, by family and outcome.",
			Buckets: latencyBuckets,
		}, []string{"project", "family", "outcome"}),
		dropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "excalibase_request_metrics_dropped_total",
			Help: "Requests not recorded because the project cap was reached.",
		}),
		serves:      serves,
		maxProjects: maxProjects,
		admitted:    map[string]bool{},
	}
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "excalibase_request_metrics_info",
		Help:        "Start time of this process; a new instance means its counters restarted.",
		ConstLabels: prometheus.Labels{"instance": uuid.NewString()},
	})
	info.Set(float64(time.Now().Unix()))
	registry.MustRegister(recorder.requests, recorder.dropped, info)
	return recorder
}

// Middleware times a request on a /{orgSlug}/{projectId} route.
func (r *Recorder) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		started := time.Now()
		wrapped := chimw.NewWrapResponseWriter(w, req.ProtoMajor)
		next.ServeHTTP(wrapped, req)
		r.record(chi.URLParam(req, "projectId"), wrapped.Status(), time.Since(started))
	})
}

func (r *Recorder) record(projectID string, status int, elapsed time.Duration) {
	if projectID == "" || !r.serves(projectID) {
		return
	}
	if !r.admit(projectID) {
		r.dropped.Inc()
		return
	}
	r.requests.WithLabelValues(projectID, family, outcome(status)).Observe(elapsed.Seconds())
}

func (r *Recorder) admit(projectID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.admitted[projectID] {
		return true
	}
	if len(r.admitted) >= r.maxProjects {
		return false
	}
	r.admitted[projectID] = true
	return true
}

func outcome(status int) string {
	switch {
	case status >= http.StatusInternalServerError:
		return "server_error"
	case status >= http.StatusBadRequest:
		return "client_error"
	default:
		return "ok"
	}
}

// Handler serves the registry in the Prometheus text format.
func (r *Recorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{})
}

// ServerMux is everything the internal listener answers: GET /metrics.
func (r *Recorder) ServerMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", r.Handler())
	return mux
}
