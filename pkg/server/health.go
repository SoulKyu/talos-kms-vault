package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// HealthServer provides health check endpoints for Kubernetes probes
type HealthServer struct {
	server *http.Server
	logger *slog.Logger
}

// NewHealthServer creates a new health server instance
func NewHealthServer(addr string, logger *slog.Logger) *HealthServer {
	return &HealthServer{
		server: &http.Server{
			Addr:         addr,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		logger: logger,
	}
}

// Start starts the health server
func (hs *HealthServer) Start(handler http.Handler) error {
	hs.server.Handler = handler
	hs.logger.Info("Starting health server", "address", hs.server.Addr)

	go func() {
		if err := hs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			hs.logger.Error("Health server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the health server
func (hs *HealthServer) Stop(ctx context.Context) error {
	hs.logger.Info("Stopping health server")
	return hs.server.Shutdown(ctx)
}

// CreateHealthHandler creates HTTP handlers for health checks
func (las *LeaderAwareServer) CreateHealthHandler() http.Handler {
	mux := http.NewServeMux()

	// Liveness probe - always returns 200 if the process is alive
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Readiness probe - returns 200 only if this instance is the leader
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		if las.IsReady() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ready")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			currentLeader := las.electionController.GetCurrentLeader()
			if currentLeader != "" {
				fmt.Fprintf(w, "not leader (current leader: %s)", currentLeader)
			} else {
				fmt.Fprint(w, "not leader (no leader elected)")
			}
		}
	})

	// Leader info endpoint - returns JSON with leadership information
	mux.HandleFunc("/leader", func(w http.ResponseWriter, r *http.Request) {
		info := las.GetLeadershipInfo()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(info)
	})

	// Metrics endpoint (placeholder for future Prometheus metrics)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		info := las.GetLeadershipInfo()

		// Simple text metrics for now
		fmt.Fprintf(w, "# HELP kms_is_leader Whether this instance is the leader\n")
		fmt.Fprintf(w, "# TYPE kms_is_leader gauge\n")
		if info.IsLeader {
			fmt.Fprintf(w, "kms_is_leader 1\n")
		} else {
			fmt.Fprintf(w, "kms_is_leader 0\n")
		}

		fmt.Fprintf(w, "# HELP kms_leadership_changes_total Total number of leadership changes\n")
		fmt.Fprintf(w, "# TYPE kms_leadership_changes_total counter\n")
		fmt.Fprintf(w, "kms_leadership_changes_total %d\n", info.LeadershipChanges)
	})

	return mux
}

// CreateHealthHandler for regular (non-leader-aware) server
func (s *Server) CreateHealthHandler() http.Handler {
	mux := http.NewServeMux()

	// Liveness probe - always returns 200 if the process is alive
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// Readiness probe - always ready for non-leader-aware mode
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ready")
	})

	// Basic info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"mode": "single-instance",
			"ready": true,
		})
	})

	return mux
}