// Package pdns provides a client for the PowerDNS Authoritative Server REST API.
//
// The Client wraps HTTP calls to the /api/v1 endpoints exposed by PowerDNS,
// supporting zone and record management (CRUD), DNSSEC rectification, and
// slave notification.
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/logger"
	"github.com/babykart/gozone/internal/models"
)

// Client provides access to the PowerDNS REST API.
type Client struct {
	baseURL  string
	apiKey   string
	serverID string
	http     *http.Client
}

// Transport-level timeouts for the PowerDNS HTTP client (m43). Each covers a
// single connection phase and is shorter than the 30s http.Client.Timeout, so a
// stuck phase (TCP dial, TLS handshake, slow response headers) fails fast with a
// phase-specific error instead of consuming the whole request budget.
const (
	// pdnsDialTimeout caps the TCP connect to the PowerDNS API (usually local or
	// same-network, so well under a second; 10s is a generous ceiling).
	pdnsDialTimeout = 10 * time.Second
	// pdnsTLSHandshakeTimeout caps the TLS handshake.
	pdnsTLSHandshakeTimeout = 10 * time.Second
	// pdnsResponseHeaderTimeout caps the wait for response headers after the
	// request is sent — the main defence against a server that accepts the
	// connection but then stalls (slowloris-style header attack).
	pdnsResponseHeaderTimeout = 15 * time.Second
	// pdnsExpectContinueTimeout caps the wait for a 100-Continue response before
	// sending a request body. Standard value; Go uses 1s by default.
	pdnsExpectContinueTimeout = 1 * time.Second
	// pdnsDialerKeepAlive is the TCP keepalive probe interval for pooled
	// connections (enables dead-connection detection).
	pdnsDialerKeepAlive = 30 * time.Second
)

// NewClient creates a new PowerDNS API client from configuration.
//
// It normalizes the API URL to ensure it ends with "/api/v1" and configures an
// HTTP client with a 30-second overall request timeout plus per-phase transport
// timeouts (dial, TLS handshake, response headers) so a stuck connection phase
// fails fast rather than burning the entire budget (m43).
func NewClient(cfg *config.PowerDNSConfig) *Client {
	baseURL := strings.TrimRight(cfg.APIURL, "/")
	if !strings.HasSuffix(baseURL, "/api/v1") {
		baseURL += "/api/v1"
	}

	dialer := &net.Dialer{
		Timeout:   pdnsDialTimeout,
		KeepAlive: pdnsDialerKeepAlive,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   pdnsTLSHandshakeTimeout,
		ResponseHeaderTimeout: pdnsResponseHeaderTimeout,
		ExpectContinueTimeout: pdnsExpectContinueTimeout,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
	}

	return &Client{
		baseURL:  baseURL,
		apiKey:   cfg.APIKey,
		serverID: cfg.ServerID,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
		},
	}
}

// maxPDNSResponseBytes caps the size of a single PowerDNS API response body
// read into memory. It is generous enough for a full zone dump (a zone with
// tens of thousands of records is well under this), yet bounded so a
// misconfigured or compromised upstream cannot exhaust server memory by
// streaming an unbounded body (m42).
const maxPDNSResponseBytes int64 = 64 << 20 // 64 MiB

// readLimitedBody reads at most limit bytes from r. It uses the limit+1 trick:
// reading one extra byte makes it possible to distinguish a body that exactly
// equals the limit (valid) from one that exceeds it (rejected), rather than
// silently truncating and handing malformed JSON to the caller. A body larger
// than limit yields an error.
func readLimitedBody(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response body exceeds %d-byte limit (possible misconfigured or compromised upstream)", limit)
	}
	return b, nil
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	url := c.baseURL + path

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
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

	respBody, err := readLimitedBody(resp.Body, maxPDNSResponseBytes)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}

	logger.Debug("pdns request", "method", method, "path", path, "status", resp.StatusCode, "bytes", len(respBody))
	return respBody, resp.StatusCode, nil
}

// doOK executes an HTTP request and checks only that the status is 2xx.
// It is used for endpoints that return an empty body on success.
func doOK(c *Client, ctx context.Context, method, path string, body interface{}) error {
	respBody, status, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return httpError(status, respBody)
	}
	return nil
}

// doUnmarshal executes an HTTP request, checks for a 2xx status, and
// unmarshals the JSON response into a value of type T.
func doUnmarshal[T any](c *Client, ctx context.Context, method, path string, body interface{}, desc string) (T, error) {
	var zero T
	respBody, status, err := c.do(ctx, method, path, body)
	if err != nil {
		return zero, err
	}
	if status < 200 || status >= 300 {
		return zero, httpError(status, respBody)
	}
	if err := json.Unmarshal(respBody, &zero); err != nil {
		return zero, fmt.Errorf("unmarshal %s: %w", desc, err)
	}
	return zero, nil
}

// serverPath returns the server-scoped URL path "/servers/<serverID>" with the
// (config-supplied) serverID path-escaped so it cannot inject extra path
// components.
func (c *Client) serverPath() string {
	return "/servers/" + url.PathEscape(c.serverID)
}

// zonePath returns the zone-scoped URL path prefix
// "/servers/<serverID>/zones/<zoneID>" with both segments path-escaped so a
// request-controlled zoneID (or a configured serverID) cannot inject extra path
// components. This closes the path-traversal surface flagged in m41 —
// identifiers are never interpolated raw into request URLs.
func (c *Client) zonePath(zoneID string) string {
	return c.serverPath() + "/zones/" + url.PathEscape(zoneID)
}

// GetServer returns a single server's info.
func (c *Client) GetServer(ctx context.Context) (*models.ServerInfo, error) {
	server, err := doUnmarshal[models.ServerInfo](c, ctx, "GET", c.serverPath(), nil, "server")
	if err != nil {
		return nil, err
	}
	return &server, nil
}

// HealthCheck performs a lightweight, uncached connectivity check against the
// PowerDNS API. It is used by readiness probes and must not rely on caching.
func (c *Client) HealthCheck(ctx context.Context) error {
	_, err := c.GetServer(ctx)
	return err
}

// GetStatistics returns global PowerDNS statistics.
func (c *Client) GetStatistics(ctx context.Context) ([]models.StatisticItem, error) {
	return doUnmarshal[[]models.StatisticItem](c, ctx, "GET", c.serverPath()+"/statistics", nil, "statistics")
}

// ListZones returns all zones without their rrsets.
//
// ?rrsets=false prevents PowerDNS from including record sets in the response,
// keeping the payload small regardless of zone size.
func (c *Client) ListZones(ctx context.Context) ([]models.Zone, error) {
	return doUnmarshal[[]models.Zone](c, ctx, "GET", c.serverPath()+"/zones?rrsets=false", nil, "zones")
}

// ListZonesWithInfo returns all zones in a single request.
//
// Record counts are not included; the former approach made one additional
// HTTP request per zone (N+1) which is replaced by a single ListZones call.
func (c *Client) ListZonesWithInfo(ctx context.Context) ([]models.ZoneWithInfo, error) {
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	info := make([]models.ZoneWithInfo, len(zones))
	for i, z := range zones {
		info[i] = models.ZoneWithInfo{Zone: z}
	}
	return info, nil
}

// GetZone returns a specific zone.
func (c *Client) GetZone(ctx context.Context, zoneID string) (*models.Zone, error) {
	zone, err := doUnmarshal[models.Zone](c, ctx, "GET", c.zonePath(zoneID), nil, "zone")
	if err != nil {
		return nil, err
	}
	return &zone, nil
}

// CreateZone creates a new zone.
func (c *Client) CreateZone(ctx context.Context, req models.ZoneCreateRequest) (*models.Zone, error) {
	if req.Kind == "" {
		req.Kind = "Native"
	}
	if req.Nameservers == nil {
		req.Nameservers = []string{}
	}

	zone, err := doUnmarshal[models.Zone](c, ctx, "POST", c.serverPath()+"/zones", req, "zone")
	if err != nil {
		return nil, err
	}
	return &zone, nil
}

// DeleteZone deletes a zone.
func (c *Client) DeleteZone(ctx context.Context, zoneID string) error {
	return doOK(c, ctx, "DELETE", c.zonePath(zoneID), nil)
}

// ListRecords returns all records (RRSets) for a zone.
func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]models.RRSet, error) {
	return c.listZoneRRSets(ctx, zoneID, "", "")
}

// ListRecord returns one or more RRSets filtered by name and (optionally)
// type. It maps to the PowerDNS API `rrset_name` / `rrset_type` query
// parameters on the zone GET endpoint, which lets callers fetch a single
// RRSet (or all RRSets for a given name) without pulling the entire zone.
//
// Pass an empty name to fetch every RRSet in the zone (equivalent to
// ListRecords). Pass a name with an empty rrType to fetch every RRSet
// matching that name (any type). Pass both to fetch one specific RRSet.
func (c *Client) ListRecord(ctx context.Context, zoneID, name, rrType string) ([]models.RRSet, error) {
	return c.listZoneRRSets(ctx, zoneID, name, rrType)
}

func (c *Client) listZoneRRSets(ctx context.Context, zoneID, name, rrType string) ([]models.RRSet, error) {
	path := c.zonePath(zoneID)
	if name != "" {
		path += "?rrset_name=" + url.QueryEscape(name)
		if rrType != "" {
			path += "&rrset_type=" + url.QueryEscape(rrType)
		}
	}

	full, err := doUnmarshal[struct {
		RRSets []models.RRSet `json:"rrsets"`
	}](c, ctx, "GET", path, nil, "rrsets")
	if err != nil {
		return nil, err
	}
	for i := range full.RRSets {
		for j := range full.RRSets[i].Records {
			if p, c, ok := models.SplitPriority(full.RRSets[i].Type, full.RRSets[i].Records[j].Content); ok {
				full.RRSets[i].Records[j].Priority = p
				full.RRSets[i].Records[j].Content = c
			}
		}
	}
	return full.RRSets, nil
}

// UpdateRecord updates an existing RRSet.
func (c *Client) UpdateRecord(ctx context.Context, zoneID string, rrset models.RRSet) error {
	rrset.ChangeType = "REPLACE"
	return c.patchZone(ctx, zoneID, []models.RRSet{rrset})
}

// DeleteRecord deletes an RRSet from a zone.
func (c *Client) DeleteRecord(ctx context.Context, zoneID string, name, recordType string) error {
	rrset := models.RRSet{
		Name:       name,
		Type:       recordType,
		ChangeType: "DELETE",
	}
	return c.patchZone(ctx, zoneID, []models.RRSet{rrset})
}

// CreateRecords creates multiple RRSets in a zone in a single PATCH call.
func (c *Client) CreateRecords(ctx context.Context, zoneID string, rrsets []models.RRSet) error {
	if len(rrsets) == 0 {
		return nil
	}

	for i := range rrsets {
		rrsets[i].ChangeType = "REPLACE"
	}
	return c.patchZone(ctx, zoneID, rrsets)
}

// PatchRecords applies a batch of RRSet changes in a single PATCH call. Unlike
// CreateRecords (which forces REPLACE), it honors each rrset's ChangeType so a
// single atomic operation can mix DELETE and REPLACE across RRSets — e.g. a
// bulk delete that drops some RRSets entirely and trims others. An empty
// ChangeType defaults to "REPLACE".
func (c *Client) PatchRecords(ctx context.Context, zoneID string, rrsets []models.RRSet) error {
	if len(rrsets) == 0 {
		return nil
	}
	for i := range rrsets {
		if rrsets[i].ChangeType == "" {
			rrsets[i].ChangeType = "REPLACE"
		}
	}
	return c.patchZone(ctx, zoneID, rrsets)
}

// patchRecord is the PATCH-body representation of a record. It carries only
// content and disabled: PowerDNS rejects a separate "priority" element in a
// PATCH (the priority must be embedded in the content for MX/SRV). Using a
// dedicated type — rather than RecordInfo, whose omitempty only hides a zero
// priority — guarantees a stray non-zero Priority can never leak into the PATCH
// body and trigger a PDNS 422 (m53).
type patchRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// patchRRSet is the PATCH-body representation of an RRSet, mirroring RRSet but
// with records projected to patchRecord (no priority element).
type patchRRSet struct {
	Name       string               `json:"name"`
	Type       string               `json:"type"`
	TTL        int                  `json:"ttl"`
	ChangeType string               `json:"changetype,omitempty"`
	Records    []patchRecord        `json:"records"`
	Comments   *models.CommentPatch `json:"comments,omitempty"`
}

func (c *Client) patchZone(ctx context.Context, zoneID string, rrsets []models.RRSet) error {
	patch := make([]patchRRSet, len(rrsets))
	for i, rr := range rrsets {
		// Preserve a nil Records slice as null (DELETE changetype); only project
		// to patchRecord when records are present.
		var recs []patchRecord
		if rr.Records != nil {
			recs = make([]patchRecord, len(rr.Records))
			for j, r := range rr.Records {
				recs[j] = patchRecord{Content: r.Content, Disabled: r.Disabled}
			}
		}
		patch[i] = patchRRSet{
			Name:       rr.Name,
			Type:       rr.Type,
			TTL:        rr.TTL,
			ChangeType: rr.ChangeType,
			Records:    recs,
			Comments:   rr.Comments,
		}
	}
	payload := map[string]interface{}{
		"rrsets": patch,
	}
	return doOK(c, ctx, "PATCH", c.zonePath(zoneID), payload)
}

// RectifyZone triggers DNSSEC rectification for a zone.
func (c *Client) RectifyZone(ctx context.Context, zoneID string) error {
	return doOK(c, ctx, "PUT", c.zonePath(zoneID)+"/rectify", nil)
}

// NotifySlaves sends NOTIFY to slave servers for a zone.
func (c *Client) NotifySlaves(ctx context.Context, zoneID string) error {
	return doOK(c, ctx, "PUT", c.zonePath(zoneID)+"/notify", nil)
}

// GetMetadata returns all zone metadata entries.
func (c *Client) GetMetadata(ctx context.Context, zoneID string) ([]models.Metadata, error) {
	return doUnmarshal[[]models.Metadata](c, ctx, "GET", c.zonePath(zoneID)+"/metadata", nil, "metadata")
}

// SetMetadata creates or replaces a zone metadata entry.
// Uses PUT with the kind in the URL path for broader compatibility across
// PowerDNS versions.
func (c *Client) SetMetadata(ctx context.Context, zoneID string, meta models.Metadata) error {
	if meta.Metadata == nil {
		meta.Metadata = []string{}
	}
	payload := map[string][]string{"metadata": meta.Metadata}
	return doOK(c, ctx, "PUT", c.zonePath(zoneID)+"/metadata/"+url.PathEscape(meta.Kind), payload)
}

// DeleteMetadata removes a zone metadata entry by kind.
func (c *Client) DeleteMetadata(ctx context.Context, zoneID string, kind string) error {
	return doOK(c, ctx, "DELETE", c.zonePath(zoneID)+"/metadata/"+url.PathEscape(kind), nil)
}

// ServerID returns the configured server ID.
func (c *Client) ServerID() string {
	return c.serverID
}

// ListTSIGKeys returns all TSIG keys for the server.
func (c *Client) ListTSIGKeys(ctx context.Context) ([]models.TSIGKey, error) {
	return doUnmarshal[[]models.TSIGKey](c, ctx, "GET", c.serverPath()+"/tsigkeys", nil, "tsigkeys")
}

// GetTSIGKey returns a single TSIG key.
func (c *Client) GetTSIGKey(ctx context.Context, id string) (*models.TSIGKey, error) {
	key, err := doUnmarshal[models.TSIGKey](c, ctx, "GET", c.serverPath()+"/tsigkeys/"+url.PathEscape(id), nil, "tsigkey")
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// CreateTSIGKey creates a new TSIG key.
func (c *Client) CreateTSIGKey(ctx context.Context, key models.TSIGKey) (*models.TSIGKey, error) {
	created, err := doUnmarshal[models.TSIGKey](c, ctx, "POST", c.serverPath()+"/tsigkeys", key, "tsigkey")
	if err != nil {
		return nil, err
	}
	return &created, nil
}

// UpdateTSIGKey updates an existing TSIG key.
func (c *Client) UpdateTSIGKey(ctx context.Context, id string, key models.TSIGKey) error {
	return doOK(c, ctx, "PUT", c.serverPath()+"/tsigkeys/"+url.PathEscape(id), key)
}

// DeleteTSIGKey deletes a TSIG key.
func (c *Client) DeleteTSIGKey(ctx context.Context, id string) error {
	return doOK(c, ctx, "DELETE", c.serverPath()+"/tsigkeys/"+url.PathEscape(id), nil)
}

// --- DNSSEC Cryptokeys ---

type createCryptoRequest struct {
	KeyType   string `json:"keytype"`
	Active    bool   `json:"active"`
	Algorithm string `json:"algorithm"`
}

// ListCryptokeys returns all DNSSEC keys for a zone.
func (c *Client) ListCryptokeys(ctx context.Context, zoneID string) ([]models.Cryptokey, error) {
	return doUnmarshal[[]models.Cryptokey](c, ctx, "GET", c.zonePath(zoneID)+"/cryptokeys", nil, "cryptokeys")
}

// CreateCryptokey creates a new DNSSEC key for a zone.
func (c *Client) CreateCryptokey(ctx context.Context, zoneID string, keyType string, active bool, algorithm string) (*models.Cryptokey, error) {
	req := createCryptoRequest{
		KeyType:   keyType,
		Active:    active,
		Algorithm: algorithm,
	}
	key, err := doUnmarshal[models.Cryptokey](c, ctx, "POST", c.zonePath(zoneID)+"/cryptokeys", req, "cryptokey")
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// ToggleCryptokey activates or deactivates a DNSSEC key.
func (c *Client) ToggleCryptokey(ctx context.Context, zoneID string, keyID int, active bool) error {
	payload := map[string]interface{}{"active": active}
	return doOK(c, ctx, "PUT", c.zonePath(zoneID)+"/cryptokeys/"+strconv.Itoa(keyID), payload)
}

// DeleteCryptokey deletes a DNSSEC key from a zone.
func (c *Client) DeleteCryptokey(ctx context.Context, zoneID string, keyID int) error {
	return doOK(c, ctx, "DELETE", c.zonePath(zoneID)+"/cryptokeys/"+strconv.Itoa(keyID), nil)
}

// Close is a no-op for the bare client, which holds no resources.
func (c *Client) Close() {}

// InvalidateZoneCache is a no-op on the bare Client (no cache layer).
func (c *Client) InvalidateZoneCache(ctx context.Context, zoneID string) {}
