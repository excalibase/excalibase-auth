package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/excalibase/auth/internal/config"
	"github.com/excalibase/auth/internal/requestmetrics"
)

// requestMetricsRecorder is nil while the request charts are off: no
// middleware is mounted and no listener starts.
func requestMetricsRecorder(settings config.RequestMetrics, serves func(projectID string) bool) *requestmetrics.Recorder {
	if !settings.Enabled {
		return nil
	}
	return requestmetrics.NewRecorder(serves, settings.MaxProjects)
}

// newRequestMetricsServer is the internal listener provisioning scrapes; the
// chart admits only provisioning to this port and the edge never routes it; a
// single host binds it to the platform-only network's address alone.
func newRequestMetricsServer(settings config.RequestMetrics, recorder *requestmetrics.Recorder) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort(settings.Address, settings.Port),
		Handler:           recorder.ServerMux(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

func serveRequestMetrics(server *http.Server) {
	log.Printf("request metrics listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("request metrics server: %v", err)
	}
}
