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

// Flattened report for tool output.

type Report struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	State             string `json:"state"`
	Severity          string `json:"severity"`
	WeaknessName      string `json:"weakness_name,omitempty"`
	CreatedAt         string `json:"created_at"`
	TriagedAt         string `json:"triaged_at,omitempty"`
	BountyAwardedAt   string `json:"bounty_awarded_at,omitempty"`
	ReporterUsername  string `json:"reporter_username,omitempty"`
	VulnInfo          string `json:"vulnerability_information,omitempty"`
	ImpactDescription string `json:"impact,omitempty"`
}
