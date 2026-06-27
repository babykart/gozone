package models

import "encoding/json"

// Zone represents a PowerDNS zone (domain).
type Zone struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	URL            string   `json:"url"`
	Kind           string   `json:"kind"`
	Serial         int64    `json:"serial"`
	NotifiedSerial int64    `json:"notified_serial"`
	Masters        []string `json:"masters"`
	DNSSEC         bool     `json:"dnssec"`
	Account        string   `json:"account"`
	Catalog        string   `json:"catalog"`
	EditedSerial   int64    `json:"edited_serial"`
	LastCheck      int64    `json:"last_check"`
}

// Record represents a DNS record within a zone.
type Record struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
	Disabled bool   `json:"disabled"`
	SetPTR   bool   `json:"set_ptr,omitempty"`
}

// RecordInfo is the PowerDNS API representation of a record with metadata.
// Priority uses omitempty because PowerDNS rejects the "priority" element in
// PATCH body — it must be embedded in the content string for MX/SRV types.
type RecordInfo struct {
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl,omitempty"`
	Priority int    `json:"priority,omitempty"`
	Disabled bool   `json:"disabled"`
}

// RRSet represents a resource record set in the PowerDNS API.
//
// Comments is a *CommentPatch (not a plain slice) so the wire format can
// distinguish between three PowerDNS PATCH states:
//   - field absent (PowerDNS preserves existing comments)
//   - field present but empty (PowerDNS purges all comments)
//   - field present with items (PowerDNS replaces the list)
//
// The standard encoding/json package treats nil slices and empty slices
// identically for omitempty purposes, which is why the wrapper is required.
type RRSet struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	TTL        int           `json:"ttl"`
	ChangeType string        `json:"changetype,omitempty"`
	Records    []RecordInfo  `json:"records"`
	Comments   *CommentPatch `json:"comments,omitempty"`
}

// Comment is a comment on an RRSet.
type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
}

// CommentPatch wraps the RRSet comment list with an explicit "clear" signal.
// MarshalJSON emits one of three wire forms to match PowerDNS PATCH semantics:
//
//   - Clear=true                 -> "comments":[]   (explicit purge)
//   - Items nil or empty         -> "comments":null (preserve; PDNS treats null
//     equivalently to absent)
//   - Items non-empty            -> "comments":[...] (replace)
//
// UnmarshalJSON always leaves Clear=false; the only way to obtain a clear
// patch is to set Clear=true on the struct directly. This keeps the
// read-then-write round trip safe: PowerDNS returns "comments":[] for an
// RRSet with no comments and a naive round trip must preserve them, not
// purge them.
type CommentPatch struct {
	Items []Comment
	Clear bool
}

// MarshalJSON implements the tri-state wire encoding described on CommentPatch.
func (c CommentPatch) MarshalJSON() ([]byte, error) {
	if c.Clear {
		return []byte("[]"), nil
	}
	if len(c.Items) == 0 {
		return []byte("null"), nil
	}
	return json.Marshal(c.Items)
}

// UnmarshalJSON parses a comments array (or null) into Items. Both "null" and
// "[]" are normalised to a nil Items slice; Clear is never set by unmarshalling.
func (c *CommentPatch) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &c.Items)
}

// ZoneCreateRequest is the payload for creating a zone.
type ZoneCreateRequest struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Nameservers []string `json:"nameservers,omitempty"`
	Masters     []string `json:"masters,omitempty"`
	Catalog     string   `json:"catalog,omitempty"`
}

// ServerInfo holds PowerDNS server statistics.
type ServerInfo struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	URL       string `json:"url"`
	Daemon    string `json:"daemon_type"`
	Version   string `json:"version"`
	ConfigURL string `json:"config_url"`
	ZonesURL  string `json:"zones_url"`
}

// StatisticItem is a single statistic key-value pair.
// Value can be a string, number, or array depending on the statistic type.
type StatisticItem struct {
	Name  string      `json:"name"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

// ZoneStatistics holds statistics for a zone.
type ZoneStatistics struct {
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Serial     int64           `json:"serial"`
	Records    int             `json:"records"`
	Statistics []StatisticItem `json:"statistics,omitempty"`
}

// ZoneWithInfo combines a zone with its record count for listing pages.
type ZoneWithInfo struct {
	Zone        Zone `json:"zone"`
	RecordCount int  `json:"record_count"`
}

// Metadata represents a zone metadata entry in the PowerDNS API.
// Each entry has a kind (e.g. "ALLOW-AXFR-FROM") and an array of values.
type Metadata struct {
	Kind     string   `json:"kind"`
	Metadata []string `json:"metadata"`
	TTL      int64    `json:"ttl,omitempty"`
}

// TSIGKey represents a TSIG (Transaction SIGnature) key used for secured DNS
// operations such as zone transfers and dynamic updates.
type TSIGKey struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
	Type      string `json:"type"`
}

// Cryptokey represents a DNSSEC cryptographic key in PowerDNS.
type Cryptokey struct {
	Type       string   `json:"type"`
	ID         int      `json:"id"`
	KeyType    string   `json:"keytype"`
	Active     bool     `json:"active"`
	Published  bool     `json:"published"`
	DNSKEY     string   `json:"dnskey"`
	DS         []string `json:"ds"`
	PrivateKey string   `json:"privatekey"`
	Algorithm  string   `json:"algorithm"`
	Bits       int      `json:"bits"`
}

// DNSSECAlgorithm describes a supported DNSSEC signing algorithm.
type DNSSECAlgorithm struct {
	Name        string
	Description string
}

// DNSSECAlgorithms returns the list of algorithms supported by PowerDNS.
func DNSSECAlgorithms() []DNSSECAlgorithm {
	return []DNSSECAlgorithm{
		{"rsasha256", "RSA/SHA-256 (8)"},
		{"rsasha512", "RSA/SHA-512 (10)"},
		{"ecdsa256", "ECDSA P-256 SHA-256 (13)"},
		{"ecdsa384", "ECDSA P-384 SHA-384 (14)"},
		{"ed25519", "Ed25519 (15)"},
		{"ed448", "Ed448 (16)"},
	}
}
