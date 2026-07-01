package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/babykart/gozone/internal/config"
	"github.com/babykart/gozone/internal/models"
	"github.com/babykart/gozone/internal/pdns"
	"github.com/babykart/gozone/internal/testutil"
)

func dnssecHandler() testutil.PDNSHandlerFunc {
	return dnssecHandlerWithCounter(nil)
}

func dnssecHandlerWithCounter(rectifyCalls *int) testutil.PDNSHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		method := r.Method

		if method == http.MethodPut && strings.Contains(path, "/rectify") {
			if rectifyCalls != nil {
				*rectifyCalls++
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"result":"Rectified"}`))
			return
		}
		if method == http.MethodGet && strings.Contains(path, "cryptokeys") && !strings.Contains(path, "cryptokeys/") {
			w.Write([]byte(`[{"type":"Cryptokey","id":1,"keytype":"ksk","active":true,"published":true,"dnskey":"...","ds":["SHA256 abc"],"algorithm":"ECDSAP256SHA256","bits":256}]`))
			return
		}
		if method == http.MethodPost && strings.Contains(path, "cryptokeys") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"type":"Cryptokey","id":2,"keytype":"ksk","active":true,"published":true,"dnskey":"...","ds":[],"algorithm":"ecdsa256","bits":256}`))
			return
		}
		if method == http.MethodPut && strings.Contains(path, "cryptokeys/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if method == http.MethodDelete && strings.Contains(path, "cryptokeys/") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if method == http.MethodGet && strings.Contains(path, "/zones/") {
			if strings.Contains(r.URL.RawQuery, "rrsets") {
				w.Write([]byte(`[{"id":"ec","name":"example.com.","kind":"Native","serial":2024010100}]`))
			} else {
				w.Write([]byte(`{"id":"example.com.","name":"example.com.","kind":"Native","serial":2024010100,"rrsets":[]}`))
			}
			return
		}
		w.Write([]byte(`[]`))
	}
}

func TestCreateCryptokey(t *testing.T) {
	var rectifyCalls int
	h, srv := newTestHandlerWithPDNS(t, dnssecHandlerWithCounter(&rectifyCalls))
	defer srv.Close()

	userID := seedUserWithHash(t, h, "cryptouser", "pass", "admin")
	user := &models.User{ID: userID, Username: "cryptouser", Role: "admin"}

	body := "keytype=ksk&algorithm=ecdsa256"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/create", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.CreateCryptokey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='create_cryptokey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log entry, got %d", count)
	}

	if rectifyCalls != 1 {
		t.Errorf("expected 1 rectify call after create, got %d", rectifyCalls)
	}
}

func TestToggleCryptokey_Activate(t *testing.T) {
	var rectifyCalls int
	h, srv := newTestHandlerWithPDNS(t, dnssecHandlerWithCounter(&rectifyCalls))
	defer srv.Close()

	userID := seedUserWithHash(t, h, "toggleuser", "pass", "admin")
	user := &models.User{ID: userID, Username: "toggleuser", Role: "admin"}

	body := "active=true"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/1/toggle", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.SetPathValue("key_id", "1")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.ToggleCryptokey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	if rectifyCalls != 1 {
		t.Errorf("expected 1 rectify call after toggle, got %d", rectifyCalls)
	}
}

func TestToggleCryptokey_Deactivate(t *testing.T) {
	var rectifyCalls int
	h, srv := newTestHandlerWithPDNS(t, dnssecHandlerWithCounter(&rectifyCalls))
	defer srv.Close()

	userID := seedUserWithHash(t, h, "deactuser", "pass", "admin")
	user := &models.User{ID: userID, Username: "deactuser", Role: "admin"}

	body := "active=false"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/1/toggle", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.SetPathValue("key_id", "1")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.ToggleCryptokey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	if rectifyCalls != 1 {
		t.Errorf("expected 1 rectify call after toggle, got %d", rectifyCalls)
	}
}

func TestDeleteCryptokey(t *testing.T) {
	var rectifyCalls int
	h, srv := newTestHandlerWithPDNS(t, dnssecHandlerWithCounter(&rectifyCalls))
	defer srv.Close()

	userID := seedUserWithHash(t, h, "delcryptouser", "pass", "admin")
	user := &models.User{ID: userID, Username: "delcryptouser", Role: "admin"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/1/delete", nil)
	r.SetPathValue("zone_id", "example.com.")
	r.SetPathValue("key_id", "1")
	r = withUserContext(r, user)
	h.DeleteCryptokey(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='delete_cryptokey'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log entry, got %d", count)
	}

	if rectifyCalls != 1 {
		t.Errorf("expected 1 rectify call after delete, got %d", rectifyCalls)
	}
}

func TestCreateCryptokey_InvalidType(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, dnssecHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}

	body := "keytype=invalid&algorithm=ecdsa256"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/create", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.CreateCryptokey(w, r)

	if !strings.Contains(w.Body.String(), "Key type must be ksk or zsk") {
		t.Errorf("expected validation error, got %s", w.Body.String())
	}
}

// TestCreateCryptokey_InvalidAlgorithm is the m33 regression test: an
// unsupported DNSSEC algorithm must be rejected before reaching PowerDNS.
func TestCreateCryptokey_InvalidAlgorithm(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, dnssecHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}

	body := "keytype=ksk&algorithm=rsa1024"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cryptokeys/create", strings.NewReader(body))
	r.SetPathValue("zone_id", "example.com.")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withUserContext(r, user)
	h.CreateCryptokey(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid algorithm") {
		t.Errorf("expected 'Invalid algorithm' in error page, got %s", w.Body.String())
	}
}

func TestViewZone_IncludesCryptokeys(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, dnssecHandler())
	defer srv.Close()

	user := &models.User{ID: 1, Username: "admin", Role: "admin"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/zones/example.com.", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, user)
	h.ViewZone(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestDNSSECAlgorithms(t *testing.T) {
	algos := models.DNSSECAlgorithms()
	if len(algos) == 0 {
		t.Fatal("expected non-empty algorithms list")
	}

	names := map[string]bool{}
	for _, a := range algos {
		if names[a.Name] {
			t.Errorf("duplicate algorithm name: %s", a.Name)
		}
		names[a.Name] = true
	}
}

func TestGetDNSSECAlgorithms(t *testing.T) {
	algos := GetDNSSECAlgorithms()
	if len(algos) == 0 {
		t.Fatal("expected non-empty GetDNSSECAlgorithms result")
	}
}

func TestListCryptokeys_Client(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"type":"Cryptokey","id":1,"keytype":"ksk","active":true,"published":true,"dnskey":"...","ds":["SHA256 abc","SHA384 def"],"algorithm":"ECDSAP256SHA256","bits":256}]`))
	}))
	defer srv.Close()

	client := pdns.NewClient(&config.PowerDNSConfig{APIURL: srv.URL, APIKey: "key", ServerID: "localhost"})

	keys, err := client.ListCryptokeys(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("ListCryptokeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].ID != 1 || keys[0].KeyType != "ksk" || !keys[0].Active {
		t.Errorf("unexpected key data: %+v", keys[0])
	}
	if len(keys[0].DS) != 2 {
		t.Errorf("expected 2 DS records, got %d", len(keys[0].DS))
	}
}

func TestClearZoneCache(t *testing.T) {
	h, srv := newTestHandlerWithPDNS(t, dnssecHandler())
	defer srv.Close()

	userID := seedUserWithHash(t, h, "clearcache", "pass", "admin")
	user := &models.User{ID: userID, Username: "clearcache", Role: "admin"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/zones/example.com./cache/clear", nil)
	r.SetPathValue("zone_id", "example.com.")
	r = withUserContext(r, user)
	h.ClearZoneCache(w, r)

	if w.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", w.Code)
	}

	var count int
	h.DB.QueryRow("SELECT COUNT(*) FROM activity_logs WHERE action='clear_zone_cache'").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 activity log entry, got %d", count)
	}
}
