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
	report.TriagedAt, _ = a["triaged_at"].(string)
	report.ClosedAt, _ = a["closed_at"].(string)
	report.BountyAwardedAt, _ = a["bounty_awarded_at"].(string)
	report.VulnInfo, _ = a["vulnerability_information"].(string)
	report.ImpactDescription, _ = a["impact"].(string)

	extractSeverity(&report, r)

	if weak := relAttrs(r, "weakness"); weak != nil {
		report.WeaknessName, _ = weak["name"].(string)
		report.CweID, _ = weak["external_id"].(string)
	}

	report.ReporterUsername = relString(r, "reporter", "username")
	report.Assignee = relString(r, "assignee", "username")
	report.ProgramHandle = relString(r, "program", "handle")
	report.AssetIdentifier = relString(r, "structured_scope", "asset_identifier")
	report.BountyAmount = sumBounties(r)

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
	if report.Severity == "" {
		report.Severity, _ = r.Attributes["severity_rating"].(string)
	}
}

func sumBounties(r Resource) float64 {
	rel, ok := r.Relationships["bounties"]
	if !ok {
		return 0
	}
	arr, ok := rel.Data.([]any)
	if !ok {
		return 0
	}
	var total float64
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		attrs, ok := m["attributes"].(map[string]any)
		if !ok {
			continue
		}
		switch v := attrs["amount"].(type) {
		case float64:
			total += v
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				total += f
			}
		}
	}
	return total
}
