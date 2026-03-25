package hackerone

import (
	"testing"
)

func TestParseCvssVector_Full(t *testing.T) {
	m := parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if m == nil {
		t.Fatal("expected non-nil CvssMetrics")
	}
	checks := []struct{ field, want string }{
		{m.AttackVector, "Network"},
		{m.AttackComplexity, "Low"},
		{m.PrivRequired, "None"},
		{m.UserInteraction, "None"},
		{m.Scope, "Unchanged"},
		{m.Confidentiality, "High"},
		{m.Integrity, "High"},
		{m.Availability, "High"},
	}
	for _, c := range checks {
		if c.field != c.want {
			t.Errorf("got %q, want %q", c.field, c.want)
		}
	}
}

func TestParseCvssVector_Partial(t *testing.T) {
	m := parseCvssVector("AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N")
	if m == nil {
		t.Fatal("expected non-nil CvssMetrics")
	}
	if m.AttackVector != "Local" {
		t.Errorf("AV: got %q, want Local", m.AttackVector)
	}
	if m.AttackComplexity != "High" {
		t.Errorf("AC: got %q, want High", m.AttackComplexity)
	}
	if m.Scope != "Changed" {
		t.Errorf("S: got %q, want Changed", m.Scope)
	}
}

func TestParseCvssVector_Empty(t *testing.T) {
	if m := parseCvssVector(""); m != nil {
		t.Error("expected nil for empty vector")
	}
}

func TestParseCvssVector_Garbage(t *testing.T) {
	if m := parseCvssVector("not-a-vector"); m != nil {
		t.Error("expected nil for garbage input")
	}
}

func TestParseCvssVector_UnknownValue(t *testing.T) {
	m := parseCvssVector("AV:X/AC:L")
	if m == nil {
		t.Fatal("expected non-nil CvssMetrics")
	}
	if m.AttackVector != "X" {
		t.Errorf("AV: got %q, want raw X", m.AttackVector)
	}
	if m.AttackComplexity != "Low" {
		t.Errorf("AC: got %q, want Low", m.AttackComplexity)
	}
}

func TestRelString(t *testing.T) {
	r := Resource{
		Relationships: map[string]Relationship{
			"reporter": {
				Data: map[string]any{
					"attributes": map[string]any{
						"username": "hacker42",
					},
				},
			},
		},
	}
	if got := relString(r, "reporter", "username"); got != "hacker42" {
		t.Errorf("got %q, want hacker42", got)
	}
	if got := relString(r, "reporter", "missing"); got != "" {
		t.Errorf("got %q for missing attr, want empty", got)
	}
	if got := relString(r, "missing_rel", "username"); got != "" {
		t.Errorf("got %q for missing rel, want empty", got)
	}
}

func TestFlattenReports_Basic(t *testing.T) {
	resources := []Resource{
		{
			ID: "12345",
			Attributes: map[string]any{
				"title":      "XSS in login",
				"state":      "new",
				"created_at": "2024-01-15T00:00:00Z",
			},
			Relationships: map[string]Relationship{
				"severity": {
					Data: map[string]any{
						"attributes": map[string]any{
							"rating":             "high",
							"score":              float64(7.5),
							"cvss_vector_string": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
						},
					},
				},
				"reporter": {
					Data: map[string]any{
						"attributes": map[string]any{
							"username": "researcher1",
						},
					},
				},
				"weakness": {
					Data: map[string]any{
						"attributes": map[string]any{
							"name":        "Cross-Site Scripting",
							"external_id": "CWE-79",
						},
					},
				},
			},
		},
	}

	reports := flattenReports(resources)
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}

	r := reports[0]
	if r.ID != "12345" {
		t.Errorf("ID: got %q", r.ID)
	}
	if r.Title != "XSS in login" {
		t.Errorf("Title: got %q", r.Title)
	}
	if r.Severity != "high" {
		t.Errorf("Severity: got %q", r.Severity)
	}
	if r.CvssScore != 7.5 {
		t.Errorf("CvssScore: got %f", r.CvssScore)
	}
	if r.CvssBreakdown == nil {
		t.Fatal("CvssBreakdown is nil")
	}
	if r.CvssBreakdown.AttackVector != "Network" {
		t.Errorf("AV: got %q", r.CvssBreakdown.AttackVector)
	}
	if r.ReporterUsername != "researcher1" {
		t.Errorf("Reporter: got %q", r.ReporterUsername)
	}
	if r.WeaknessName != "Cross-Site Scripting" {
		t.Errorf("Weakness: got %q", r.WeaknessName)
	}
	if r.CweID != "CWE-79" {
		t.Errorf("CWE: got %q", r.CweID)
	}
}

func TestFlattenReports_Empty(t *testing.T) {
	reports := flattenReports(nil)
	if len(reports) != 0 {
		t.Errorf("got %d reports for nil input", len(reports))
	}
}

func TestSumBountiesWithBonus(t *testing.T) {
	r := Resource{
		Relationships: map[string]Relationship{
			"bounties": {
				Data: []any{
					map[string]any{
						"attributes": map[string]any{
							"amount":              float64(500),
							"awarded_bonus_amount": "100.00",
						},
					},
					map[string]any{
						"attributes": map[string]any{
							"amount":              "250.50",
							"awarded_bonus_amount": float64(50),
						},
					},
				},
			},
		},
	}
	total, bonus := sumBountiesWithBonus(r)
	if total != 750.50 {
		t.Errorf("total: got %f, want 750.50", total)
	}
	if bonus != 150.00 {
		t.Errorf("bonus: got %f, want 150.00", bonus)
	}
}

func TestSumBountiesWithBonus_NoBounties(t *testing.T) {
	r := Resource{}
	total, bonus := sumBountiesWithBonus(r)
	if total != 0 {
		t.Errorf("total: got %f for no bounties, want 0", total)
	}
	if bonus != 0 {
		t.Errorf("bonus: got %f for no bounties, want 0", bonus)
	}
}

func TestExtractSeverity_ScoreAsString(t *testing.T) {
	r := Resource{
		ID: "1",
		Relationships: map[string]Relationship{
			"severity": {
				Data: map[string]any{
					"attributes": map[string]any{
						"rating": "critical",
						"score":  "8.7",
					},
				},
			},
		},
	}
	reports := flattenReports([]Resource{r})
	if reports[0].CvssScore != 8.7 {
		t.Errorf("CvssScore from string: got %f, want 8.7", reports[0].CvssScore)
	}
}

func TestFlattenReports_GroupAssignee(t *testing.T) {
	r := Resource{
		ID:         "1",
		Attributes: map[string]any{},
		Relationships: map[string]Relationship{
			"assignee": {
				Data: map[string]any{
					"attributes": map[string]any{
						"name": "Security Team",
					},
				},
			},
		},
	}
	reports := flattenReports([]Resource{r})
	if reports[0].Assignee != "Security Team" {
		t.Errorf(
			"group assignee: got %q, want Security Team",
			reports[0].Assignee,
		)
	}
}

func TestFlattenReports_UserAssigneeTakesPrecedence(t *testing.T) {
	r := Resource{
		ID:         "1",
		Attributes: map[string]any{},
		Relationships: map[string]Relationship{
			"assignee": {
				Data: map[string]any{
					"attributes": map[string]any{
						"username": "alice",
						"name":     "Alice Smith",
					},
				},
			},
		},
	}
	reports := flattenReports([]Resource{r})
	if reports[0].Assignee != "alice" {
		t.Errorf("user assignee: got %q, want alice", reports[0].Assignee)
	}
}

func TestFlattenReports_NewFields(t *testing.T) {
	r := Resource{
		ID: "1",
		Attributes: map[string]any{
			"updated_at":                  "2024-06-01T00:00:00Z",
			"last_activity_at":            "2024-06-02T00:00:00Z",
			"last_reporter_activity_at":   "2024-05-30T00:00:00Z",
			"last_program_activity_at":    "2024-06-01T12:00:00Z",
			"cve_ids":                     "CVE-2024-1234",
		},
	}
	reports := flattenReports([]Resource{r})
	rpt := reports[0]
	if rpt.UpdatedAt != "2024-06-01T00:00:00Z" {
		t.Errorf("updated_at: got %q", rpt.UpdatedAt)
	}
	if rpt.LastActivityAt != "2024-06-02T00:00:00Z" {
		t.Errorf("last_activity_at: got %q", rpt.LastActivityAt)
	}
	if rpt.LastReporterActivityAt != "2024-05-30T00:00:00Z" {
		t.Errorf("last_reporter_activity_at: got %q", rpt.LastReporterActivityAt)
	}
	if rpt.LastProgramActivityAt != "2024-06-01T12:00:00Z" {
		t.Errorf("last_program_activity_at: got %q", rpt.LastProgramActivityAt)
	}
	if rpt.CveIDs != "CVE-2024-1234" {
		t.Errorf("cve_ids: got %q", rpt.CveIDs)
	}
}

func TestExtractActivityDetails_BountyFloat(t *testing.T) {
	act := Activity{}
	extractActivityDetails(&act, map[string]any{
		"bounty_amount": float64(750),
	})
	if act.BountyAmount != 750 {
		t.Errorf("bounty float: got %f, want 750", act.BountyAmount)
	}
}

func TestExtractActivityDetails_ScopeChange(t *testing.T) {
	act := Activity{}
	extractActivityDetails(&act, map[string]any{
		"old_scope": "*.example.com",
		"new_scope": "api.example.com",
	})
	if act.OldValue != "*.example.com" {
		t.Errorf("old_scope: got %q", act.OldValue)
	}
	if act.NewValue != "api.example.com" {
		t.Errorf("new_scope: got %q", act.NewValue)
	}
}

func TestFlattenReports_SeverityFallback(t *testing.T) {
	r := Resource{
		ID: "1",
		Attributes: map[string]any{
			"severity_rating": "medium",
		},
	}
	reports := flattenReports([]Resource{r})
	if reports[0].Severity != "medium" {
		t.Errorf(
			"severity fallback: got %q, want medium",
			reports[0].Severity,
		)
	}
}
