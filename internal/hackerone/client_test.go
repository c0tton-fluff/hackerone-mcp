package hackerone

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateReportID_Valid(t *testing.T) {
	for _, id := range []string{"1", "12345", "9999999"} {
		if err := ValidateReportID(id); err != nil {
			t.Errorf("ValidateReportID(%q): unexpected error: %v", id, err)
		}
	}
}

func TestValidateReportID_Invalid(t *testing.T) {
	for _, id := range []string{"", "abc", "12.5", "12 34", "-1", "0x1F"} {
		if err := ValidateReportID(id); err == nil {
			t.Errorf("ValidateReportID(%q): expected error", id)
		}
	}
}

func TestResolveProgram_Override(t *testing.T) {
	c := NewClient("id", "key", "default_prog")
	if got := c.resolveProgram("override"); got != "override" {
		t.Errorf("got %q, want override", got)
	}
}

func TestResolveProgram_Default(t *testing.T) {
	c := NewClient("id", "key", "default_prog")
	if got := c.resolveProgram(""); got != "default_prog" {
		t.Errorf("got %q, want default_prog", got)
	}
}

func TestValidStates(t *testing.T) {
	expected := []string{
		"new", "triaged", "resolved",
		"not-applicable", "informative", "duplicate", "spam",
	}
	for _, s := range expected {
		if !ValidStates[s] {
			t.Errorf("state %q should be valid", s)
		}
	}
	if ValidStates["invalid"] {
		t.Error("state 'invalid' should not be valid")
	}
}

func TestListReports_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			page++
			var body string
			switch page {
			case 1:
				body = `{"data":[{"id":"100","type":"report","attributes":{"title":"Bug A","state":"new","created_at":"2024-01-01T00:00:00Z"}}],"links":{"next":"NEXT"}}`
			case 2:
				body = `{"data":[{"id":"200","type":"report","attributes":{"title":"Bug B","state":"triaged","created_at":"2024-02-01T00:00:00Z"}}],"links":{}}`
			}
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	// Re-register handler with correct next URL
	page = 0
	srv.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			page++
			var body string
			switch page {
			case 1:
				body = `{"data":[{"id":"100","type":"report","attributes":{"title":"Bug A","state":"new","created_at":"2024-01-01T00:00:00Z"}}],"links":{"next":"` + srv.URL + `/page2"}}`
			case 2:
				body = `{"data":[{"id":"200","type":"report","attributes":{"title":"Bug B","state":"triaged","created_at":"2024-02-01T00:00:00Z"}}],"links":{}}`
			}
			w.Write([]byte(body))
		},
	)

	reports, err := c.ListReports(context.Background(), ReportFilter{
		Limit: 50,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	if reports[0].Title != "Bug A" || reports[1].Title != "Bug B" {
		t.Errorf("titles: %q, %q", reports[0].Title, reports[1].Title)
	}
}

func TestGetActivities_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewServer(nil)
	defer srv.Close()

	srv.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			page++
			var body string
			switch page {
			case 1:
				body = `{"data":[{"id":"1","type":"activity-comment","attributes":{"message":"first","created_at":"2024-01-01T00:00:00Z"}}],"links":{"next":"` + srv.URL + `/page2"}}`
			case 2:
				body = `{"data":[{"id":"2","type":"activity-state-change","attributes":{"message":"closed","created_at":"2024-01-02T00:00:00Z"}}],"links":{}}`
			}
			w.Write([]byte(body))
		},
	)

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	activities, err := c.GetActivities(context.Background(), "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(activities) != 2 {
		t.Fatalf("got %d activities, want 2", len(activities))
	}
	if activities[0].Message != "first" {
		t.Errorf("activity 0 message: %q", activities[0].Message)
	}
	if activities[1].Type != "activity-state-change" {
		t.Errorf("activity 1 type: %q", activities[1].Type)
	}
}

func TestValidTransitionStates(t *testing.T) {
	if ValidTransitionStates["new"] {
		t.Error("'new' should not be a valid transition state")
	}
	for _, s := range []string{
		"triaged", "resolved", "not-applicable",
		"informative", "duplicate", "spam",
	} {
		if !ValidTransitionStates[s] {
			t.Errorf("state %q should be a valid transition", s)
		}
	}
}

func TestUpdateSeverity_Validation(t *testing.T) {
	c := NewClient("test", "key", "prog")
	err := c.UpdateSeverity(context.Background(), "abc", "high", "")
	if err == nil {
		t.Error("expected error for invalid report ID")
	}
}

func TestAssignReport_Validation(t *testing.T) {
	c := NewClient("test", "key", "prog")
	err := c.AssignReport(context.Background(), "abc", "alice")
	if err == nil {
		t.Error("expected error for invalid report ID")
	}
}

func TestAssignReport_CorrectBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	_ = c.AssignReport(context.Background(), "12345", "alice")

	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	data := parsed["data"].(map[string]any)
	if data["type"] != "assignee" {
		t.Errorf("type: got %q, want assignee", data["type"])
	}
	attrs := data["attributes"].(map[string]any)
	if attrs["username"] != "alice" {
		t.Errorf("username: got %q, want alice", attrs["username"])
	}
}

func TestGetActivities_BountyAmount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := `{"data":[{"id":"1","type":"activity-bounty-awarded","attributes":{"message":"Thanks!","bounty_amount":"500.00","created_at":"2024-01-01T00:00:00Z"}}],"links":{}}`
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	activities, err := c.GetActivities(context.Background(), "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(activities) != 1 {
		t.Fatalf("got %d activities, want 1", len(activities))
	}
	if activities[0].BountyAmount != 500.0 {
		t.Errorf("bounty_amount: got %f, want 500.0", activities[0].BountyAmount)
	}
}

func TestGetActivities_ChangeValues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := `{"data":[{"id":"1","type":"activity-severity-updated","attributes":{"message":"bumped","old_severity":"medium","new_severity":"high","created_at":"2024-01-01T00:00:00Z"}}],"links":{}}`
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	activities, err := c.GetActivities(context.Background(), "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if activities[0].OldValue != "medium" {
		t.Errorf("old_value: got %q, want medium", activities[0].OldValue)
	}
	if activities[0].NewValue != "high" {
		t.Errorf("new_value: got %q, want high", activities[0].NewValue)
	}
}

func TestCachedPrograms_ThreadSafe(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.Write([]byte(`{"data":[{"id":"1","type":"program","attributes":{"handle":"test-prog"}}],"links":{}}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := c.cachedPrograms(context.Background())
			errs <- err
		}()
	}
	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Errorf("API called %d times, want 1 (cached)", calls)
	}
}

func TestUpdateState_CorrectEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	_ = c.UpdateState(context.Background(), "12345", "triaged", "test")
	if gotMethod != "POST" {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/reports/12345/state_changes" {
		t.Errorf("path: got %q, want /reports/12345/state_changes", gotPath)
	}
}

func TestMarkDuplicate_CorrectEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	_ = c.MarkDuplicate(context.Background(), "111", "222")
	if gotPath != "/reports/111/state_changes" {
		t.Errorf("path: got %q, want /reports/111/state_changes", gotPath)
	}
}

func TestUpdateSeverity_CorrectEndpoint(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	_ = c.UpdateSeverity(context.Background(), "12345", "high", "")
	if gotMethod != "POST" {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/reports/12345/severities" {
		t.Errorf("path: got %q, want /reports/12345/severities", gotPath)
	}
}

func TestGetActivities_UsesIncrementalEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			if r.URL.Query().Get("report_id") != "12345" {
				t.Errorf("report_id param: got %q", r.URL.Query().Get("report_id"))
			}
			body := `{"data":[{"id":"1","type":"activity-comment","attributes":{"message":"hello","created_at":"2024-01-01T00:00:00Z"}}],"links":{}}`
			w.Write([]byte(body))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	activities, err := c.GetActivities(context.Background(), "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/incremental/activities" {
		t.Errorf("path: got %q, want /incremental/activities", gotPath)
	}
	if len(activities) != 1 || activities[0].Message != "hello" {
		t.Errorf("activities: got %+v", activities)
	}
}

func TestAddSummary_RequestShape(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	err := c.AddSummary(context.Background(), "12345", "Root cause was X")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/reports/12345/summaries" {
		t.Errorf("path: got %q", gotPath)
	}
	var parsed map[string]any
	json.Unmarshal(gotBody, &parsed)
	data := parsed["data"].(map[string]any)
	if data["type"] != "summary" {
		t.Errorf("type: got %q", data["type"])
	}
	attrs := data["attributes"].(map[string]any)
	if attrs["content"] != "Root cause was X" {
		t.Errorf("content: got %q", attrs["content"])
	}
}

func TestUpdateCVEs_RequestShape(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	err := c.UpdateCVEs(
		context.Background(), "12345",
		[]string{"CVE-2026-0001", "CVE-2026-0002"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "PUT" {
		t.Errorf("method: got %q, want PUT", gotMethod)
	}
	if gotPath != "/reports/12345/cves" {
		t.Errorf("path: got %q", gotPath)
	}
	var parsed map[string]any
	json.Unmarshal(gotBody, &parsed)
	data := parsed["data"].(map[string]any)
	if data["type"] != "cve" {
		t.Errorf("type: got %q", data["type"])
	}
	attrs := data["attributes"].(map[string]any)
	ids := attrs["cve_ids"].([]any)
	if len(ids) != 2 || ids[0] != "CVE-2026-0001" {
		t.Errorf("cve_ids: got %v", ids)
	}
}

func TestCloseComments_RequestShape(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	err := c.CloseComments(context.Background(), "12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "PUT" {
		t.Errorf("method: got %q, want PUT", gotMethod)
	}
	if gotPath != "/reports/12345/close_comments" {
		t.Errorf("path: got %q", gotPath)
	}
}

func TestManageRetest_Request(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	err := c.ManageRetest(
		context.Background(), "12345", "request", "Please verify fix",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/reports/12345/retests" {
		t.Errorf("path: got %q", gotPath)
	}
	var parsed map[string]any
	json.Unmarshal(gotBody, &parsed)
	data := parsed["data"].(map[string]any)
	if data["type"] != "retest-request" {
		t.Errorf("type: got %q", data["type"])
	}
}

func TestManageRetest_Approve(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	err := c.ManageRetest(context.Background(), "12345", "approve", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method: got %q", gotMethod)
	}
	if gotPath != "/reports/12345/retests/approve" {
		t.Errorf("path: got %q", gotPath)
	}
}

func TestManageRetest_Cancel(t *testing.T) {
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			w.WriteHeader(200)
			w.Write([]byte(`{}`))
		},
	))
	defer srv.Close()
	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	err := c.ManageRetest(context.Background(), "12345", "cancel", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "DELETE" {
		t.Errorf("method: got %q, want DELETE", gotMethod)
	}
	if gotPath != "/reports/12345/retests/cancel" {
		t.Errorf("path: got %q", gotPath)
	}
}

func TestManageRetest_InvalidAction(t *testing.T) {
	c := NewClient("test", "key", "prog")
	err := c.ManageRetest(context.Background(), "12345", "nope", "")
	if err == nil {
		t.Error("expected error for invalid action")
	}
}

func TestGetAnalytics_RequestShape(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			if r.URL.Query().Get("filter[program][]") == "" {
				t.Error("missing filter[program][] param")
			}
			w.Write([]byte(`{"data":{"attributes":{"reports_count":42}}}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL

	result, err := c.GetAnalytics(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/analytics" {
		t.Errorf("path: got %q", gotPath)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestCreateReport_RequestShape(t *testing.T) {
	var gotPath, gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(201)
			w.Write([]byte(`{"data":{"id":"99999","type":"report","attributes":{"title":"Test Bug"}}}`))
		},
	))
	defer srv.Close()

	c := NewClient("test", "key", "prog")
	c.http = srv.Client()
	c.baseURL = srv.URL
	c.programCache = []Program{{ID: "100", Handle: "prog"}}

	id, err := c.CreateReport(context.Background(), CreateReportParams{
		Title:    "Test Bug",
		VulnInfo: "Steps to reproduce...",
		Severity: "high",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != "POST" {
		t.Errorf("method: got %q, want POST", gotMethod)
	}
	if gotPath != "/reports" {
		t.Errorf("path: got %q", gotPath)
	}
	if id != "99999" {
		t.Errorf("returned ID: got %q, want 99999", id)
	}
	var parsed map[string]any
	json.Unmarshal(gotBody, &parsed)
	data := parsed["data"].(map[string]any)
	if data["type"] != "report" {
		t.Errorf("type: got %q", data["type"])
	}
	attrs := data["attributes"].(map[string]any)
	if attrs["title"] != "Test Bug" {
		t.Errorf("title: got %q", attrs["title"])
	}
}
