package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthStatus represents the response format for health check endpoints.
type HealthStatus struct {
	Status string `json:"status"`
}

// healthResponse returns the status of each dependency. If any check fails,
// the overall status is "degraded" or "unhealthy".
type healthResponse struct {
	Status   string            `json:"status"`
	Checks   map[string]string `json:"checks,omitempty"`
	Database string            `json:"database,omitempty"`
	PowerDNS string            `json:"powerdns,omitempty"`
}

// HealthReady checks the readiness of all critical dependencies.
//
// It verifies:
//   - Database connectivity (Ping)
//   - PowerDNS API connectivity (GetServer)
//
// Returns HTTP 200 with {"status": "ok", ...} when all checks pass.
// Returns HTTP 503 with {"status": "degraded", ...} when any check fails.
// GET /health/ready
func (h *Handler) HealthReady(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status: "ok",
		Checks: make(map[string]string),
	}

	if err := h.DB.Ping(); err != nil {
		resp.Checks["database"] = "error: " + err.Error()
		resp.Status = "degraded"
	} else {
		resp.Checks["database"] = "ok"
	}

	if _, err := h.PDNS.GetServer(); err != nil {
		resp.Checks["powerdns"] = "error: " + err.Error()
		resp.Status = "degraded"
	} else {
		resp.Checks["powerdns"] = "ok"
	}

	statusCode := http.StatusOK
	if resp.Status != "ok" {
		statusCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(resp) // #nosec G104
}

// HealthLive returns a simple liveness probe indicating the process is running.
//
// This endpoint performs no dependency checks and always returns HTTP 200.
// It is suitable for Kubernetes liveness probes or basic uptime monitoring.
// GET /health/live
func (h *Handler) HealthLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","alive":true}`)) // #nosec G104
}
