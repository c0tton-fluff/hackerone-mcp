package hackerone

import (
	"context"
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
	err := c.AssignReport(context.Background(), "abc", "1", "user")
	if err == nil {
		t.Error("expected error for invalid report ID")
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
