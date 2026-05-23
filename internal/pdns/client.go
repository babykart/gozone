package pdns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/models"
)

// Client provides access to the PowerDNS REST API.
type Client struct {
	baseURL  string
	apiKey   string
	serverID string
	http     *http.Client
}

// NewClient creates a new PowerDNS API client.
func NewClient(cfg *config.PowerDNSConfig) *Client {
	baseURL := strings.TrimRight(cfg.APIURL, "/")
	if !strings.HasSuffix(baseURL, "api/v1") {
		if !strings.HasSuffix(baseURL, "/api/v1") {
			baseURL += "/api/v1"
		}
	}

	return &Client{
		baseURL:  baseURL,
		apiKey:   cfg.APIKey,
		serverID: cfg.ServerID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) do(method, path string, body interface{}) ([]byte, int, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	log.Printf("[pdns] %s %s -> %d (%d bytes)", method, path, resp.StatusCode, len(respBody))
	return respBody, resp.StatusCode, nil
}

// GetServers returns the list of PowerDNS servers.
func (c *Client) GetServers() ([]models.ServerInfo, error) {
	body, status, err := c.do("GET", "/servers", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var servers []models.ServerInfo
	if err := json.Unmarshal(body, &servers); err != nil {
		return nil, fmt.Errorf("unmarshal servers: %w", err)
	}
	return servers, nil
}

// GetServer returns a single server's info.
func (c *Client) GetServer() (*models.ServerInfo, error) {
	body, status, err := c.do("GET", "/servers/"+c.serverID, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var server models.ServerInfo
	if err := json.Unmarshal(body, &server); err != nil {
		return nil, fmt.Errorf("unmarshal server: %w", err)
	}
	return &server, nil
}

// GetStatistics returns global PowerDNS statistics.
func (c *Client) GetStatistics() ([]models.StatisticItem, error) {
	body, status, err := c.do("GET", "/servers/"+c.serverID+"/statistics", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var stats []models.StatisticItem
	if err := json.Unmarshal(body, &stats); err != nil {
		return nil, fmt.Errorf("unmarshal statistics: %w", err)
	}
	return stats, nil
}

// ListZones returns all zones.
func (c *Client) ListZones() ([]models.Zone, error) {
	body, status, err := c.do("GET", "/servers/"+c.serverID+"/zones", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var zones []models.Zone
	if err := json.Unmarshal(body, &zones); err != nil {
		return nil, fmt.Errorf("unmarshal zones: %w", err)
	}
	return zones, nil
}

// GetZone returns a specific zone.
func (c *Client) GetZone(zoneID string) (*models.Zone, error) {
	body, status, err := c.do("GET", "/servers/"+c.serverID+"/zones/"+zoneID, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var zone models.Zone
	if err := json.Unmarshal(body, &zone); err != nil {
		return nil, fmt.Errorf("unmarshal zone: %w", err)
	}
	return &zone, nil
}

// CreateZone creates a new zone.
func (c *Client) CreateZone(req models.ZoneCreateRequest) (*models.Zone, error) {
	if req.Kind == "" {
		req.Kind = "Native"
	}
	if req.Nameservers == nil {
		req.Nameservers = []string{}
	}

	body, status, err := c.do("POST", "/servers/"+c.serverID+"/zones", req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var zone models.Zone
	if err := json.Unmarshal(body, &zone); err != nil {
		return nil, fmt.Errorf("unmarshal zone: %w", err)
	}
	return &zone, nil
}

// DeleteZone deletes a zone.
func (c *Client) DeleteZone(zoneID string) error {
	_, status, err := c.do("DELETE", "/servers/"+c.serverID+"/zones/"+zoneID, nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("unexpected status %d", status)
	}
	return nil
}

// ListRecords returns all records (RRSets) for a zone.
func (c *Client) ListRecords(zoneID string) ([]models.RRSet, error) {
	body, status, err := c.do("GET", "/servers/"+c.serverID+"/zones/"+zoneID, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("unexpected status %d: %s", status, string(body))
	}

	var zone models.Zone
	if err := json.Unmarshal(body, &zone); err != nil {
		return nil, fmt.Errorf("unmarshal zone for records: %w", err)
	}

	// The zone response in newer PowerDNS versions includes RRSets
	var full struct {
		RRSets []models.RRSet `json:"rrsets"`
	}
	if err := json.Unmarshal(body, &full); err != nil {
		return nil, fmt.Errorf("unmarshal rrsets: %w", err)
	}
	return full.RRSets, nil
}

// CreateRecord creates a new RRSet in a zone.
func (c *Client) CreateRecord(zoneID string, rrset models.RRSet) error {
	rrset.ChangeType = "REPLACE"
	return c.patchZone(zoneID, []models.RRSet{rrset})
}

// UpdateRecord updates an existing RRSet.
func (c *Client) UpdateRecord(zoneID string, rrset models.RRSet) error {
	rrset.ChangeType = "REPLACE"
	return c.patchZone(zoneID, []models.RRSet{rrset})
}

// DeleteRecord deletes an RRSet from a zone.
func (c *Client) DeleteRecord(zoneID string, name, recordType string) error {
	rrset := models.RRSet{
		Name:       name,
		Type:       recordType,
		ChangeType: "DELETE",
	}
	return c.patchZone(zoneID, []models.RRSet{rrset})
}

func (c *Client) patchZone(zoneID string, rrsets []models.RRSet) error {
	payload := map[string]interface{}{
		"rrsets": rrsets,
	}

	_, status, err := c.do("PATCH", "/servers/"+c.serverID+"/zones/"+zoneID, payload)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("unexpected status %d", status)
	}
	return nil
}

// RectifyZone triggers DNSSEC rectification for a zone.
func (c *Client) RectifyZone(zoneID string) error {
	_, status, err := c.do("PUT", "/servers/"+c.serverID+"/zones/"+zoneID+"/rectify", nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("unexpected status %d", status)
	}
	return nil
}

// NotifySlaves sends NOTIFY to slave servers for a zone.
func (c *Client) NotifySlaves(zoneID string) error {
	_, status, err := c.do("PUT", "/servers/"+c.serverID+"/zones/"+zoneID+"/notify", nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("unexpected status %d", status)
	}
	return nil
}

// ServerID returns the configured server ID.
func (c *Client) ServerID() string {
	return c.serverID
}
