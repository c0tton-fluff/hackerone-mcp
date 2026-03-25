package hackerone

import (
	"strconv"
	"strings"
)

// cvssLabels maps CVSS 3.x metric abbreviations to human-readable values.
var cvssLabels = map[string]map[string]string{
	"AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
	"AC": {"L": "Low", "H": "High"},
	"PR": {"N": "None", "L": "Low", "H": "High"},
	"UI": {"N": "None", "R": "Required"},
	"S":  {"U": "Unchanged", "C": "Changed"},
	"C":  {"N": "None", "L": "Low", "H": "High"},
	"I":  {"N": "None", "L": "Low", "H": "High"},
	"A":  {"N": "None", "L": "Low", "H": "High"},
}

// cvssNaturalLanguage maps CVSS metrics to natural-language fragments for readable output.
var cvssNaturalLanguage = map[string]map[string]string{
	"AV": {"N": "network attack", "A": "adjacent network attack", "L": "local attack", "P": "physical attack"},
	"AC": {"L": "low complexity", "H": "high complexity"},
	"PR": {"N": "no privileges needed", "L": "low privileges needed", "H": "high privileges needed"},
	"UI": {"N": "no user interaction", "R": "user interaction required"},
}

// activityDisplayNames maps raw API activity types to human-readable names.
var activityDisplayNames = map[string]string{
	"activity-bug-triaged":             "Triaged",
	"activity-bug-new":                 "New",
	"activity-bug-needs-more-info":     "Needs More Info",
	"activity-bug-informative":         "Closed as Informative",
	"activity-bug-not-applicable":      "Closed as N/A",
	"activity-bug-duplicate":           "Closed as Duplicate",
	"activity-bug-spam":                "Closed as Spam",
	"activity-bug-resolved":            "Resolved",
	"activity-bug-reopened":            "Reopened",
	"activity-bounty-awarded":          "Bounty Awarded",
	"activity-bounty-suggested":        "Bounty Suggested",
	"activity-comment":                 "Comment",
	"activity-group-assigned-to-bug":   "Assigned to Group",
	"activity-user-assigned-to-bug":    "Assigned to User",
	"activity-swag-awarded":            "Swag Awarded",
	"activity-agreed-on-going-public":  "Agreed on Disclosure",
	"activity-report-became-public":    "Report Disclosed",
	"activity-cve-id-added":            "CVE Added",
	"activity-report-severity-updated": "Severity Updated",
	"activity-report-title-updated":    "Title Updated",
	"activity-external-user-joined":    "External User Joined",
	"activity-external-user-removed":   "External User Removed",
	"activity-nobody-assigned-to-bug":  "Unassigned",
}

// cvssLabel resolves a single CVSS metric:value pair to its label.
func cvssLabel(metric, value string) string {
	if m, ok := cvssLabels[metric]; ok {
		if label, ok := m[value]; ok {
			return label
		}
		return value
	}
	return ""
}

// cvssDescription returns a natural-language summary of a CVSS vector.
func cvssDescription(vector string) string {
	if vector == "" {
		return ""
	}
	var parts []string
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		if m, ok := cvssNaturalLanguage[kv[0]]; ok {
			if desc, ok := m[kv[1]]; ok {
				parts = append(parts, desc)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

// parseCvssVector parses a CVSS 3.x vector string into components.
func parseCvssVector(vector string) *CvssMetrics {
	if vector == "" {
		return nil
	}

	vals := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		if label := cvssLabel(kv[0], kv[1]); label != "" {
			vals[kv[0]] = label
		}
	}

	if len(vals) == 0 {
		return nil
	}
	return &CvssMetrics{
		AttackVector:     vals["AV"],
		AttackComplexity: vals["AC"],
		PrivRequired:     vals["PR"],
		UserInteraction:  vals["UI"],
		Scope:            vals["S"],
		Confidentiality:  vals["C"],
		Integrity:        vals["I"],
		Availability:     vals["A"],
	}
}

// extractActivityDetails pulls bounty_amount, bonus_amount, and old/new
// change values from activity attributes based on activity type.
func extractActivityDetails(act *Activity, attrs map[string]any) {
	switch v := attrs["bounty_amount"].(type) {
	case float64:
		act.BountyAmount = v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			act.BountyAmount = f
		}
	}
	switch v := attrs["bonus_amount"].(type) {
	case float64:
		act.BonusAmount = v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			act.BonusAmount = f
		}
	}
	act.OldValue, _ = attrs["old_value"].(string)
	act.NewValue, _ = attrs["new_value"].(string)
	if act.OldValue == "" {
		act.OldValue, _ = attrs["old_scope"].(string)
	}
	if act.NewValue == "" {
		act.NewValue, _ = attrs["new_scope"].(string)
	}
	if act.OldValue == "" {
		act.OldValue, _ = attrs["old_severity"].(string)
	}
	if act.NewValue == "" {
		act.NewValue, _ = attrs["new_severity"].(string)
	}
}

// activityDisplayName returns the human-readable name for an activity type.
func activityDisplayName(actType string) string {
	if name, ok := activityDisplayNames[actType]; ok {
		return name
	}
	return strings.TrimPrefix(actType, "activity-")
}

// relAttrs extracts nested relationship attributes from a Resource.
func relAttrs(r Resource, name string) map[string]any {
	rel, ok := r.Relationships[name]
	if !ok {
		return nil
	}
	data, ok := rel.Data.(map[string]any)
	if !ok {
		return nil
	}
	attrs, _ := data["attributes"].(map[string]any)
	return attrs
}

// relString extracts a single string from a relationship's attributes.
func relString(r Resource, rel, attr string) string {
	a := relAttrs(r, rel)
	if a == nil {
		return ""
	}
	s, _ := a[attr].(string)
	return s
}

// flattenReports converts JSON:API resources into flat Report structs.
func flattenReports(resources []Resource) []Report {
	reports := make([]Report, 0, len(resources))
	for _, r := range resources {
		reports = append(reports, flattenOneReport(r))
	}
	return reports
}

func flattenOneReport(r Resource) Report {
	a := r.Attributes
	report := Report{ID: r.ID}

	report.Title, _ = a["title"].(string)
	report.State, _ = a["state"].(string)
	report.CreatedAt, _ = a["created_at"].(string)
	report.UpdatedAt, _ = a["updated_at"].(string)
	report.TriagedAt, _ = a["triaged_at"].(string)
	report.ClosedAt, _ = a["closed_at"].(string)
	report.BountyAwardedAt, _ = a["bounty_awarded_at"].(string)
	report.LastActivityAt, _ = a["last_activity_at"].(string)
	report.LastReporterActivityAt, _ = a["last_reporter_activity_at"].(string)
	report.LastProgramActivityAt, _ = a["last_program_activity_at"].(string)
	report.CveIDs, _ = a["cve_ids"].(string)
	report.VulnInfo, _ = a["vulnerability_information"].(string)
	report.ImpactDescription, _ = a["impact"].(string)
	report.IssueTrackerRef, _ = a["issue_tracker_reference_id"].(string)

	extractSeverity(&report, r)

	if weak := relAttrs(r, "weakness"); weak != nil {
		report.WeaknessName, _ = weak["name"].(string)
		report.CweID, _ = weak["external_id"].(string)
	}

	report.ReporterUsername = relString(r, "reporter", "username")
	report.Assignee = relString(r, "assignee", "username")
	if report.Assignee == "" {
		report.Assignee = relString(r, "assignee", "name")
	}
	report.ProgramHandle = relString(r, "program", "handle")
	report.AssetIdentifier = relString(r, "structured_scope", "asset_identifier")
	report.AssetType = relString(r, "structured_scope", "asset_type")
	report.BountyAmount, report.BountyBonusAmount = sumBountiesWithBonus(r)
	report.SLA = extractSLA(a)
	report.Attachments = extractAttachments(r)

	return report
}

func extractSeverity(report *Report, r Resource) {
	if sev := relAttrs(r, "severity"); sev != nil {
		report.Severity, _ = sev["rating"].(string)
		switch v := sev["score"].(type) {
		case float64:
			report.CvssScore = v
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				report.CvssScore = f
			}
		}
		report.CvssVector, _ = sev["cvss_vector_string"].(string)
	}
	report.CvssBreakdown = parseCvssVector(report.CvssVector)
	report.CvssDescription = cvssDescription(report.CvssVector)
	if report.Severity == "" {
		report.Severity, _ = r.Attributes["severity_rating"].(string)
	}
}

func sumBountiesWithBonus(r Resource) (float64, float64) {
	rel, ok := r.Relationships["bounties"]
	if !ok {
		return 0, 0
	}
	arr, ok := rel.Data.([]any)
	if !ok {
		return 0, 0
	}
	var total, bonus float64
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		attrs, ok := m["attributes"].(map[string]any)
		if !ok {
			continue
		}
		total += parseFloatField(attrs, "amount")
		bonus += parseFloatField(attrs, "awarded_bonus_amount")
	}
	return total, bonus
}

func parseFloatField(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func extractSLA(attrs map[string]any) *SLATimers {
	type field struct {
		elapsed string
		missAt  string
	}
	fields := []struct {
		setElapsed func(*SLATimers, float64)
		setMissAt  func(*SLATimers, string)
		elapsed    string
		missAt     string
	}{
		{
			func(s *SLATimers, v float64) { s.FirstResponseElapsed = v },
			func(s *SLATimers, v string) { s.FirstResponseMissAt = v },
			"timer_first_program_response_elapsed_time",
			"timer_first_program_response_miss_at",
		},
		{
			func(s *SLATimers, v float64) { s.TriageElapsed = v },
			func(s *SLATimers, v string) { s.TriageMissAt = v },
			"timer_report_triage_elapsed_time",
			"timer_report_triage_miss_at",
		},
		{
			func(s *SLATimers, v float64) { s.BountyElapsed = v },
			func(s *SLATimers, v string) { s.BountyMissAt = v },
			"timer_bounty_awarded_elapsed_time",
			"timer_bounty_awarded_miss_at",
		},
		{
			func(s *SLATimers, v float64) { s.ResolutionElapsed = v },
			func(s *SLATimers, v string) { s.ResolutionMissAt = v },
			"timer_report_resolved_elapsed_time",
			"timer_report_resolved_miss_at",
		},
	}

	sla := &SLATimers{}
	hasData := false
	for _, f := range fields {
		if v, ok := attrs[f.elapsed]; ok && v != nil {
			hasData = true
			switch n := v.(type) {
			case float64:
				f.setElapsed(sla, n)
			}
		}
		if v, ok := attrs[f.missAt]; ok && v != nil {
			if s, ok := v.(string); ok && s != "" {
				hasData = true
				f.setMissAt(sla, s)
			}
		}
	}
	if !hasData {
		return nil
	}
	return sla
}

func extractAttachments(r Resource) []Attachment {
	rel, ok := r.Relationships["attachments"]
	if !ok {
		return nil
	}
	arr, ok := rel.Data.([]any)
	if !ok {
		return nil
	}
	var atts []Attachment
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		attrs, ok := m["attributes"].(map[string]any)
		if !ok {
			continue
		}
		att := Attachment{ID: id}
		att.FileName, _ = attrs["file_name"].(string)
		att.ContentType, _ = attrs["content_type"].(string)
		att.ExpiringURL, _ = attrs["expiring_url"].(string)
		att.CreatedAt, _ = attrs["created_at"].(string)
		switch v := attrs["file_size"].(type) {
		case float64:
			att.FileSize = v
		}
		atts = append(atts, att)
	}
	return atts
}
