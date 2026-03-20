package hackerone

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfter_Seconds(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "5")
	got := parseRetryAfter(h)
	if got != 5*time.Second {
		t.Errorf("got %v, want 5s", got)
	}
}

func TestParseRetryAfter_Empty(t *testing.T) {
	h := http.Header{}
	got := parseRetryAfter(h)
	if got != 2*time.Second {
		t.Errorf("got %v, want 2s default", got)
	}
}

func TestParseRetryAfter_Negative(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "-1")
	got := parseRetryAfter(h)
	if got != 2*time.Second {
		t.Errorf("got %v, want 2s for negative", got)
	}
}

func TestParseRetryAfter_Capped(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "120")
	got := parseRetryAfter(h)
	if got != 60*time.Second {
		t.Errorf("got %v, want 60s cap", got)
	}
}

func TestDoOnce_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"ok":true}`))
		},
	))
	defer srv.Close()

	c := &Client{
		http:  srv.Client(),
		apiID: "test", apiKey: "key",
	}
	data, dur, err := c.doOnce(
		context.Background(), "GET", srv.URL, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dur != 0 {
		t.Errorf("retryAfter: got %v, want 0", dur)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("body: got %q", data)
	}
}

func TestDoOnce_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(429)
		},
	))
	defer srv.Close()

	c := &Client{
		http:  srv.Client(),
		apiID: "test", apiKey: "key",
	}
	_, dur, err := c.doOnce(
		context.Background(), "GET", srv.URL, nil,
	)
	if err == nil {
		t.Fatal("expected error for 429")
	}
	if dur != 3*time.Second {
		t.Errorf("retryAfter: got %v, want 3s", dur)
	}
}

func TestDoOnce_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"not found"}`))
		},
	))
	defer srv.Close()

	c := &Client{
		http:  srv.Client(),
		apiID: "test", apiKey: "key",
	}
	_, _, err := c.doOnce(
		context.Background(), "GET", srv.URL, nil,
	)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestDo_RetriesOn429(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			n := attempts.Add(1)
			if n <= 2 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(429)
				return
			}
			w.Write([]byte(`{"ok":true}`))
		},
	))
	defer srv.Close()

	c := &Client{
		http:  srv.Client(),
		apiID: "test", apiKey: "key",
	}
	data, err := c.do(
		context.Background(), "GET", srv.URL, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("body: got %q", data)
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts: got %d, want 3", got)
	}
}

func TestFetchAllPages_MultiPage(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			page++
			var body string
			switch page {
			case 1:
				body = `{"data":[{"id":"1","type":"report","attributes":{}}],"links":{"next":"` + "REPLACE" + `"}}`
			case 2:
				body = `{"data":[{"id":"2","type":"report","attributes":{}}],"links":{}}`
			default:
				t.Error("unexpected page request")
				w.WriteHeader(500)
				return
			}
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := &Client{
		http:    srv.Client(),
		apiID:   "test",
		apiKey:  "key",
		baseURL: srv.URL,
	}

	// Patch page 1 response to include real next URL
	page = 0
	srv.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			page++
			var body string
			switch page {
			case 1:
				body = `{"data":[{"id":"1","type":"report","attributes":{}}],"links":{"next":"` + srv.URL + `/page2"}}`
			case 2:
				body = `{"data":[{"id":"2","type":"report","attributes":{}}],"links":{}}`
			}
			w.Write([]byte(body))
		},
	)

	resources, err := c.fetchAllPages(context.Background(), srv.URL+"/page1", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2", len(resources))
	}
	if resources[0].ID != "1" || resources[1].ID != "2" {
		t.Errorf("IDs: got %s, %s", resources[0].ID, resources[1].ID)
	}
}

func TestFetchAllPages_RespectsLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := `{"data":[{"id":"1","type":"r","attributes":{}},{"id":"2","type":"r","attributes":{}},{"id":"3","type":"r","attributes":{}}],"links":{}}`
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := &Client{
		http:    srv.Client(),
		apiID:   "test",
		apiKey:  "key",
		baseURL: srv.URL,
	}
	resources, err := c.fetchAllPages(context.Background(), srv.URL+"/reports", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("got %d resources, want 2 (limit)", len(resources))
	}
}

func TestFetchAllPages_RejectsForeignURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := `{"data":[{"id":"1","type":"r","attributes":{}}],"links":{"next":"https://evil.com/steal"}}`
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := &Client{
		http:    srv.Client(),
		apiID:   "test",
		apiKey:  "key",
		baseURL: srv.URL,
	}
	_, err := c.fetchAllPages(context.Background(), srv.URL+"/reports", 0)
	if err == nil {
		t.Fatal("expected error for foreign pagination URL")
	}
}

func TestDoOnce_BasicAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok || user != "myid" || pass != "mykey" {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`ok`))
		},
	))
	defer srv.Close()

	c := &Client{
		http:  srv.Client(),
		apiID: "myid", apiKey: "mykey",
	}
	data, _, err := c.doOnce(
		context.Background(), "GET", srv.URL, nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("body: got %q", data)
	}
}
