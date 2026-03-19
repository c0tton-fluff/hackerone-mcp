package hackerone

// JSON:API envelope types for HackerOne API responses.

type ListResponse struct {
	Data  []Resource `json:"data"`
	Links PageLinks  `json:"links,omitempty"`
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
	CreatedAfter  string
	CreatedBefore string
	Limit         int
}

// Flattened report for tool output.

type Report struct {
	ID                string  `json:"id"`
	Title             string  `json:"title"`
	State             string  `json:"state"`
	Severity          string  `json:"severity"`
	CvssScore         float64 `json:"cvss_score,omitempty"`
	CvssVector        string  `json:"cvss_vector,omitempty"`
	WeaknessName      string  `json:"weakness_name,omitempty"`
	CweID             string  `json:"cwe_id,omitempty"`
	CreatedAt         string  `json:"created_at"`
	TriagedAt         string  `json:"triaged_at,omitempty"`
	ClosedAt          string  `json:"closed_at,omitempty"`
	BountyAwardedAt   string  `json:"bounty_awarded_at,omitempty"`
	BountyAmount      float64 `json:"bounty_amount,omitempty"`
	ReporterUsername  string  `json:"reporter_username,omitempty"`
	ProgramHandle    string  `json:"program_handle,omitempty"`
	VulnInfo          string  `json:"vulnerability_information,omitempty"`
	ImpactDescription string  `json:"impact,omitempty"`
	AssetIdentifier   string  `json:"asset_identifier,omitempty"`
}

type Program struct {
	ID     string `json:"id"`
	Handle string `json:"handle"`
}
