package hackerone

// JSON:API envelope types for HackerOne API responses.

type ListResponse struct {
	Data  []Resource `json:"data"`
	Links PageLinks  `json:"links"`
}

type SingleResponse struct {
	Data Resource `json:"data"`
}

type Resource struct {
	ID            string                  `json:"id"`
	Type          string                  `json:"type"`
	Attributes    map[string]any          `json:"attributes"`
	Relationships map[string]Relationship `json:"relationships,omitempty"`
}

type Relationship struct {
	Data any `json:"data,omitempty"`
}

type PageLinks struct {
	Next string `json:"next,omitempty"`
	Prev string `json:"prev,omitempty"`
}

// ReportFilter holds all supported filters for listing reports.
type ReportFilter struct {
	Program       string
	State         string
	Severity      string
	Reporter      string
	Assignee      string
	Keyword       string
	CreatedAfter  string
	CreatedBefore string
	TriagedAfter  string
	TriagedBefore string
	ClosedAfter   string
	ClosedBefore  string
	WeaknessID    string
	ReportIDs     []string
	Sort          string
	Limit         int
}

// Flattened report for tool output.

type Report struct {
	ID                       string       `json:"id"`
	Title                    string       `json:"title"`
	State                    string       `json:"state"`
	Severity                 string       `json:"severity"`
	CvssScore                float64      `json:"cvss_score,omitzero"`
	CvssVector               string       `json:"cvss_vector,omitempty"`
	CvssBreakdown            *CvssMetrics `json:"cvss_breakdown,omitempty"`
	WeaknessName             string       `json:"weakness_name,omitempty"`
	CweID                    string       `json:"cwe_id,omitempty"`
	CreatedAt                string       `json:"created_at"`
	UpdatedAt                string       `json:"updated_at,omitempty"`
	TriagedAt                string       `json:"triaged_at,omitempty"`
	ClosedAt                 string       `json:"closed_at,omitempty"`
	BountyAwardedAt          string       `json:"bounty_awarded_at,omitempty"`
	LastActivityAt           string       `json:"last_activity_at,omitempty"`
	LastReporterActivityAt   string       `json:"last_reporter_activity_at,omitempty"`
	LastProgramActivityAt    string       `json:"last_program_activity_at,omitempty"`
	CveIDs                   string       `json:"cve_ids,omitempty"`
	BountyAmount             float64      `json:"bounty_amount,omitzero"`
	ReporterUsername         string       `json:"reporter_username,omitempty"`
	Assignee                 string       `json:"assignee,omitempty"`
	ProgramHandle            string       `json:"program_handle,omitempty"`
	VulnInfo                 string       `json:"vulnerability_information,omitempty"`
	ImpactDescription        string       `json:"impact,omitempty"`
	AssetIdentifier          string       `json:"asset_identifier,omitempty"`
}

type CvssMetrics struct {
	AttackVector    string `json:"attack_vector,omitempty"`
	AttackComplexity string `json:"attack_complexity,omitempty"`
	PrivRequired    string `json:"privileges_required,omitempty"`
	UserInteraction string `json:"user_interaction,omitempty"`
	Scope           string `json:"scope,omitempty"`
	Confidentiality string `json:"confidentiality,omitempty"`
	Integrity       string `json:"integrity,omitempty"`
	Availability    string `json:"availability,omitempty"`
}

type Program struct {
	ID     string `json:"id"`
	Handle string `json:"handle"`
}

type Member struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
}

type Activity struct {
	ID           string  `json:"id"`
	Type         string  `json:"type"`
	Message      string  `json:"message,omitempty"`
	Internal     bool    `json:"internal,omitzero"`
	CreatedAt    string  `json:"created_at"`
	Actor        string  `json:"actor,omitempty"`
	BountyAmount float64 `json:"bounty_amount,omitzero"`
	OldValue     string  `json:"old_value,omitempty"`
	NewValue     string  `json:"new_value,omitempty"`
}
