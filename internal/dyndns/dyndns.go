// Package dyndns implements a DynDNS 2 protocol endpoint for dynamic DNS
// updates. It authenticates users via HTTP Basic Auth, finds the matching
// zone in PowerDNS, and creates or replaces A/AAAA records.
package dyndns

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/babykart/gozone/internal/database"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
)

// Handler provides DynDNS 2 protocol support.
//
// It authenticates users against the local user database and updates
// PowerDNS records accordingly.
type Handler struct {
	DB     *database.DB
	PDNS   pdns.ZoneService
	Domain string // Allow dyndns updates for *.domain
}

// NewHandler creates a new DynDNS handler.
//
// Parameters:
//   - db: database connection for authenticating users
//   - pdnsClient: PowerDNS API client for updating records
//   - domain: optional base domain restriction (empty means all zones)
func NewHandler(db *database.DB, pdnsClient pdns.ZoneService, domain string) *Handler {
	return &Handler{
		DB:     db,
		PDNS:   pdnsClient,
		Domain: domain,
	}
}

// ServeHTTP handles DynDNS update requests at the /nic/update endpoint.
//
// It implements the DynDNS 2 protocol subset:
//   - Authentication via HTTP Basic Auth against the local user database
//   - IP resolution from "myip", "ip" query parameters, or the client's remote address
//   - Comma-separated hostname support (multiple hostnames in one request)
//   - Returns "good <ip>" on success, "badauth" on authentication failure,
//     "nohost" when the zone cannot be found, "dnserr" on PowerDNS errors
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract query parameters
	hostname := r.URL.Query().Get("hostname")
	myip := r.URL.Query().Get("myip")

	// myip can also be in the path for some clients
	if myip == "" {
		myip = r.URL.Query().Get("ip")
	}

	// If myip is empty, use the client's IP
	if myip == "" {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		myip = ip
	}

	if hostname == "" {
		http.Error(w, "nohost", http.StatusBadRequest)
		return
	}

	// Basic auth
	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="DynDNS"`)
		http.Error(w, "badauth", http.StatusUnauthorized)
		return
	}

	// Validate user credentials
	if !h.validateUser(username, password) {
		logger.Warn("dyndns auth failed", "username", username)
		http.Error(w, "badauth", http.StatusUnauthorized)
		return
	}

	// Parse the IP
	parsedIP := net.ParseIP(myip)
	if parsedIP == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// Determine record type
	recordType := "A"
	if parsedIP.To4() == nil {
		recordType = "AAAA"
	}

	// Process each hostname (comma-separated)
	hostnames := strings.Split(hostname, ",")
	var results []string

	for _, host := range hostnames {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		// Find the zone this host belongs to
		zoneName, err := h.findZone(host)
		if err != nil {
			results = append(results, fmt.Sprintf("nohost %s", host))
			continue
		}

		// Update or create the record
		if err := h.updateRecord(zoneName, host, recordType, myip); err != nil {
			logger.Error("dyndns update failed", "host", host, "error", err)
			results = append(results, fmt.Sprintf("dnserr %s", host))
			continue
		}

		results = append(results, fmt.Sprintf("good %s", myip))
	}

	if len(results) == 0 {
		http.Error(w, "nohost", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- DynDNS protocol returns plain text, no HTML rendering
	w.Write([]byte(strings.Join(results, "\n")))
}

func (h *Handler) validateUser(username, password string) bool {
	var passwordHash string
	err := h.DB.QueryRow(
		"SELECT password_hash FROM users WHERE username = ? AND enabled = 1",
		username,
	).Scan(&passwordHash)
	if err != nil {
		return false
	}

	// Compare with bcrypt
	// The password is already hashed during registration
	// For DynDNS, we store a separate dyndns password or use the main password
	// Here we check if the password matches
	return checkPassword(passwordHash, password)
}

func (h *Handler) findZone(hostname string) (string, error) {
	// Try to find the most specific zone that contains this hostname
	zones, err := h.PDNS.ListZones()
	if err != nil {
		return "", err
	}

	var bestMatch string
	hostname = strings.TrimRight(hostname, ".") + "."

	for _, zone := range zones {
		zoneName := strings.TrimRight(zone.Name, ".") + "."
		if strings.HasSuffix(hostname, "."+zoneName) || hostname == zoneName {
			if len(zoneName) > len(bestMatch) {
				bestMatch = zone.Name
			}
		}
	}

	if bestMatch == "" {
		return "", fmt.Errorf("no zone found for %s", hostname)
	}

	return bestMatch, nil
}

func (h *Handler) updateRecord(zoneName, hostname, recordType, ip string) error {
	// Get the record name relative to the zone
	recordName := hostname
	if hostname == zoneName {
		recordName = zoneName
	}

	// Create/update the RRSet
	rrset := models.RRSet{
		Name: recordName,
		Type: recordType,
		TTL:  60,
		Records: []models.RecordInfo{
			{
				Content:  ip,
				Disabled: false,
			},
		},
		ChangeType: "REPLACE",
	}

	return h.PDNS.UpdateRecord(zoneName, rrset)
}

// checkPassword compares a plaintext password against a bcrypt hash.
func checkPassword(hash, password string) bool {
	// For simplicity, we directly compare - in production, use bcrypt
	// This is overridden to use bcrypt.CompareHashAndPassword
	err := compareBcrypt(hash, password)
	return err == nil
}
