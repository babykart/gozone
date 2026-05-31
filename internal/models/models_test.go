package models

import (
	"encoding/json"
	"testing"
	"time"
)

func TestUserIsAdmin(t *testing.T) {
	tests := []struct {
		user  User
		admin bool
	}{
		{User{Role: "admin"}, true},
		{User{Role: "user"}, false},
		{User{Role: ""}, false},
		{User{Role: "Admin"}, false},
	}

	for _, tt := range tests {
		got := tt.user.IsAdmin()
		if got != tt.admin {
			t.Errorf("User{Role: %q}.IsAdmin() = %v, want %v", tt.user.Role, got, tt.admin)
		}
	}
}

func TestUser_JSON_PasswordHashExcluded(t *testing.T) {
	user := User{
		ID:           1,
		Username:     "admin",
		Email:        "admin@example.com",
		PasswordHash: "$2a$12$secret-hash-value",
		Role:         "admin",
		Enabled:      true,
	}

	data, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("marshal User: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal User: %v", err)
	}

	if _, ok := decoded["password_hash"]; ok {
		t.Error("password_hash must not appear in JSON output")
	}
	if v, ok := decoded["username"]; !ok || v != "admin" {
		t.Errorf("expected username 'admin', got %v", decoded["username"])
	}
}

func TestAPIKey_JSON_KeyHashExcluded(t *testing.T) {
	now := time.Now()
	apikey := APIKey{
		ID:          1,
		UserID:      1,
		KeyHash:     "sha256-secret-api-key-hash",
		Description: "my key",
		LastUsedAt:  &now,
		CreatedAt:   now,
	}

	data, err := json.Marshal(apikey)
	if err != nil {
		t.Fatalf("marshal APIKey: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal APIKey: %v", err)
	}

	if _, ok := decoded["key_hash"]; ok {
		t.Error("key_hash must not appear in JSON output")
	}
	if v, ok := decoded["description"]; !ok || v != "my key" {
		t.Errorf("expected description 'my key', got %v", decoded["description"])
	}
}

func TestUser_JSON_RoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	original := User{
		ID:        42,
		Username:  "jdoe",
		Email:     "jdoe@example.com",
		FirstName: "John",
		LastName:  "Doe",
		Role:      "user",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded User
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %d, want %d", decoded.ID, original.ID)
	}
	if decoded.Username != original.Username {
		t.Errorf("Username: got %s, want %s", decoded.Username, original.Username)
	}
	if decoded.Email != original.Email {
		t.Errorf("Email: got %s, want %s", decoded.Email, original.Email)
	}
	if decoded.Role != original.Role {
		t.Errorf("Role: got %s, want %s", decoded.Role, original.Role)
	}
	if decoded.PasswordHash != "" {
		t.Error("PasswordHash must be empty after deserialization")
	}
}

func TestAPIKey_JSON_RoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	original := APIKey{
		ID:          7,
		UserID:      42,
		KeyHash:     "should-not-serialize",
		Description: "production key",
		LastUsedAt:  &now,
		CreatedAt:   now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded APIKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %d, want %d", decoded.ID, original.ID)
	}
	if decoded.UserID != original.UserID {
		t.Errorf("UserID: got %d, want %d", decoded.UserID, original.UserID)
	}
	if decoded.Description != original.Description {
		t.Errorf("Description: got %s, want %s", decoded.Description, original.Description)
	}
	if decoded.KeyHash != "" {
		t.Error("KeyHash must be empty after deserialization")
	}
}

func TestActivityLog_JSON(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	userID := int64(1)
	zoneID := "example.com"
	log := ActivityLog{
		ID:        1,
		UserID:    &userID,
		ZoneID:    &zoneID,
		Action:    "create_zone",
		Details:   "Created zone example.com",
		CreatedAt: now,
	}

	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ActivityLog
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Action != "create_zone" {
		t.Errorf("Action: got %s, want create_zone", decoded.Action)
	}
	if *decoded.ZoneID != "example.com" {
		t.Errorf("ZoneID: got %s, want example.com", *decoded.ZoneID)
	}
}

func TestSetting_JSON(t *testing.T) {
	original := Setting{ID: 1, Key: "theme", Value: "dark"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Setting
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Key != "theme" || decoded.Value != "dark" {
		t.Errorf("got %s=%s, want theme=dark", decoded.Key, decoded.Value)
	}
}

func TestZone_JSON(t *testing.T) {
	original := Zone{
		ID:     "example.com",
		Name:   "example.com",
		Kind:   "Native",
		Serial: 2024010101,
		DNSSEC: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Zone
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "example.com" {
		t.Errorf("Name: got %s, want example.com", decoded.Name)
	}
	if decoded.DNSSEC != true {
		t.Error("DNSSEC must be true")
	}
}

func TestRecord_JSON(t *testing.T) {
	original := Record{
		Name:     "www",
		Type:     "A",
		Content:  "192.168.1.1",
		TTL:      3600,
		Priority: 10,
		Disabled: false,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Record
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "www" || decoded.Type != "A" {
		t.Errorf("got %s %s, want www A", decoded.Name, decoded.Type)
	}
}

func TestRecordInfo_JSON(t *testing.T) {
	original := RecordInfo{
		Name:     "www",
		Type:     "A",
		Content:  "10.0.0.1",
		TTL:      300,
		Priority: 0,
		Disabled: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded RecordInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Content != "10.0.0.1" {
		t.Errorf("Content: got %s, want 10.0.0.1", decoded.Content)
	}
}

func TestRRSet_JSON(t *testing.T) {
	original := RRSet{
		Name:       "www.example.com",
		Type:       "A",
		TTL:        300,
		ChangeType: "REPLACE",
		Records: []RecordInfo{
			{Content: "1.2.3.4", Disabled: false},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded RRSet
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "www.example.com" {
		t.Errorf("Name: got %s, want www.example.com", decoded.Name)
	}
	if len(decoded.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(decoded.Records))
	}
	if decoded.Records[0].Content != "1.2.3.4" {
		t.Errorf("Record content: got %s, want 1.2.3.4", decoded.Records[0].Content)
	}
}

func TestComment_JSON(t *testing.T) {
	original := Comment{Content: "test comment", Account: "admin", ModifiedAt: 123456}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Comment
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Content != "test comment" {
		t.Errorf("Content: got %s, want test comment", decoded.Content)
	}
}

func TestZoneCreateRequest_JSON(t *testing.T) {
	original := ZoneCreateRequest{
		Name:        "example.org",
		Kind:        "Native",
		Nameservers: []string{"ns1.example.org", "ns2.example.org"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ZoneCreateRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "example.org" {
		t.Errorf("Name: got %s, want example.org", decoded.Name)
	}
	if len(decoded.Nameservers) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(decoded.Nameservers))
	}
}

func TestServerInfo_JSON(t *testing.T) {
	original := ServerInfo{
		ID:      "localhost",
		Type:    "Server",
		URL:     "/api/v1/servers/localhost",
		Daemon:  "authoritative",
		Version: "4.8.0",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ServerInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Version != "4.8.0" {
		t.Errorf("Version: got %s, want 4.8.0", decoded.Version)
	}
}

func TestStatisticItem_JSON(t *testing.T) {
	original := StatisticItem{Name: "udp-queries", Type: "StatisticItem", Value: "12345"}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded StatisticItem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Value != "12345" {
		t.Errorf("Value: got %s, want 12345", decoded.Value)
	}
}

func TestZoneStatistics_JSON(t *testing.T) {
	original := ZoneStatistics{
		Name:    "example.com",
		Kind:    "Native",
		Serial:  2024010101,
		Records: 42,
		Statistics: []StatisticItem{
			{Name: "qtype-A", Value: "10"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ZoneStatistics
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "example.com" || decoded.Records != 42 {
		t.Errorf("got %s %d, want example.com 42", decoded.Name, decoded.Records)
	}
}

func TestMetadata_JSON(t *testing.T) {
	original := Metadata{
		Kind:     "ALLOW-AXFR-FROM",
		Metadata: []string{"192.0.2.0/24", "2001:db8::/32"},
		TTL:      3600,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Metadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Kind != "ALLOW-AXFR-FROM" {
		t.Errorf("Kind: got %s, want ALLOW-AXFR-FROM", decoded.Kind)
	}
	if len(decoded.Metadata) != 2 {
		t.Fatalf("expected 2 metadata values, got %d", len(decoded.Metadata))
	}
	if decoded.Metadata[0] != "192.0.2.0/24" {
		t.Errorf("Metadata[0]: got %s, want 192.0.2.0/24", decoded.Metadata[0])
	}
	if decoded.TTL != 3600 {
		t.Errorf("TTL: got %d, want 3600", decoded.TTL)
	}
}

func TestMetadata_JSON_EmptyMetadata(t *testing.T) {
	original := Metadata{
		Kind:     "PRESIGNED",
		Metadata: []string{},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Metadata
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Kind != "PRESIGNED" {
		t.Errorf("Kind: got %s, want PRESIGNED", decoded.Kind)
	}
	if len(decoded.Metadata) != 0 {
		t.Errorf("expected 0 metadata values, got %d", len(decoded.Metadata))
	}
}

func TestTSIGKey_JSON(t *testing.T) {
	original := TSIGKey{
		Name:      "my-key.",
		ID:        "my-key.",
		Algorithm: "hmac-sha256",
		Key:       "c2VjcmV0LWtleS1tYXRlcmlhbA==",
		Type:      "TSIGKey",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TSIGKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Name != "my-key." {
		t.Errorf("Name: got %s, want my-key.", decoded.Name)
	}
	if decoded.Algorithm != "hmac-sha256" {
		t.Errorf("Algorithm: got %s, want hmac-sha256", decoded.Algorithm)
	}
	if decoded.Type != "TSIGKey" {
		t.Errorf("Type: got %s, want TSIGKey", decoded.Type)
	}
}

func TestTSIGKey_JSON_List(t *testing.T) {
	original := []TSIGKey{
		{Name: "key1.", ID: "key1.", Algorithm: "hmac-sha256", Key: "data1", Type: "TSIGKey"},
		{Name: "key2.", ID: "key2.", Algorithm: "hmac-sha512", Key: "data2", Type: "TSIGKey"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded []TSIGKey
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(decoded))
	}
	if decoded[1].Algorithm != "hmac-sha512" {
		t.Errorf("Algorithm[1]: got %s, want hmac-sha512", decoded[1].Algorithm)
	}
}
