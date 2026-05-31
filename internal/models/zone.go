package models

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
	Priority int    `json:"priority"`
	Disabled bool   `json:"disabled"`
	SetPTR   bool   `json:"set_ptr,omitempty"`
}

// RecordInfo is the PowerDNS API representation of a record with metadata.
type RecordInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Disabled bool   `json:"disabled"`
}

// RRSet represents a resource record set in the PowerDNS API.
type RRSet struct {
	Name       string       `json:"name"`
	Type       string       `json:"type"`
	TTL        int          `json:"ttl"`
	ChangeType string       `json:"changetype,omitempty"`
	Records    []RecordInfo `json:"records"`
	Comments   []Comment    `json:"comments,omitempty"`
}

// Comment is a comment on an RRSet.
type Comment struct {
	Content    string `json:"content"`
	Account    string `json:"account,omitempty"`
	ModifiedAt int64  `json:"modified_at,omitempty"`
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
type StatisticItem struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
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
