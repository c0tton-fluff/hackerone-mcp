package hackerone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

var validReportID = regexp.MustCompile(`^\d+$`)

const baseURL = "https://api.hackerone.com/v1"

type Client struct {
	http    *http.Client
	apiID   string
	apiKey  string
	program string
}

func NewClient(apiID, apiKey, program string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		apiID:   apiID,
		apiKey:  apiKey,
		program: program,
	}
}

func (c *Client) Program() string { return c.program }

// ValidateReportID checks that a report ID is numeric only.
func ValidateReportID(id string) error {
	if !validReportID.MatchString(id) {
		return fmt.Errorf("invalid report ID %q: must be numeric", id)
	}
	return nil
}

func (c *Client) get(
	ctx context.Context, path string,
) ([]byte, error) {
	return c.do(ctx, http.MethodGet, path, nil)
}

func (c *Client) post(
	ctx context.Context, path string, body any,
) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	return c.do(ctx, http.MethodPost, path, payload)
}

func (c *Client) do(
	ctx context.Context,
	method, path string,
	body []byte,
) ([]byte, error) {
	url := baseURL + path

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.SetBasicAuth(c.apiID, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		body := string(data)
		if len(body) > 200 {
			body = body[:200] + "..."
		}
		return nil, fmt.Errorf(
			"%s %s returned %d: %s",
			method, path, resp.StatusCode, body,
		)
	}

	return data, nil
}

// ListReports returns reports filtered by state and severity.
func (c *Client) ListReports(
	ctx context.Context, state, severity string, pageSize int,
) ([]Report, error) {
	path := fmt.Sprintf(
		"/reports?filter[program][]=%s&page[size]=%d",
		url.QueryEscape(c.program), pageSize,
	)
	if state != "" {
		path += "&filter[state][]=" + url.QueryEscape(state)
	}
	if severity != "" {
		path += "&filter[severity][]=" + url.QueryEscape(severity)
	}

	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	reports := flattenReports(resp.Data)
	if reports == nil {
		reports = []Report{}
	}
	return reports, nil
}

// GetReport returns a single report by ID.
func (c *Client) GetReport(
	ctx context.Context, reportID string,
) (*Report, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/reports/%s", reportID)

	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp SingleResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	reports := flattenReports([]Resource{resp.Data})
	if len(reports) == 0 {
		return nil, fmt.Errorf("report %s not found", reportID)
	}
	return &reports[0], nil
}

// AddComment posts an internal or public comment on a report.
func (c *Client) AddComment(
	ctx context.Context,
	reportID, message string,
	internal bool,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	path := fmt.Sprintf("/reports/%s/activities", reportID)
	body := map[string]any{
		"data": map[string]any{
			"type": "activity-comment",
			"attributes": map[string]any{
				"message":  message,
				"internal": internal,
			},
		},
	}

	_, err := c.post(ctx, path, body)
	return err
}

// ValidStates contains valid report states for the HackerOne API.
var ValidStates = map[string]bool{
	"new":            true,
	"triaged":        true,
	"resolved":       true,
	"not-applicable": true,
	"informative":    true,
	"duplicate":      true,
	"spam":           true,
}

// UpdateState changes report state (e.g. triaged, resolved).
func (c *Client) UpdateState(
	ctx context.Context,
	reportID, state, message string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if !ValidStates[state] {
		return fmt.Errorf("invalid state %q: must be one of new, triaged, resolved, not-applicable, informative, duplicate, spam", state)
	}
	path := fmt.Sprintf("/reports/%s/state_change", reportID)
	body := map[string]any{
		"data": map[string]any{
			"type": "state-change",
			"attributes": map[string]any{
				"state":   state,
				"message": message,
			},
		},
	}

	_, err := c.post(ctx, path, body)
	return err
}

// MaxBountyAmount is the upper bound for a single bounty award.
const MaxBountyAmount = 50000.0

// AwardBounty grants a bounty on a report.
func (c *Client) AwardBounty(
	ctx context.Context,
	reportID string,
	amount float64,
	message string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if amount > MaxBountyAmount {
		return fmt.Errorf("bounty amount $%.2f exceeds maximum $%.2f", amount, MaxBountyAmount)
	}
	path := fmt.Sprintf("/reports/%s/bounties", reportID)
	body := map[string]any{
		"data": map[string]any{
			"type": "bounty",
			"attributes": map[string]any{
				"amount":  amount,
				"message": message,
			},
		},
	}

	_, err := c.post(ctx, path, body)
	return err
}

// GetProgramScope returns structured scopes for the program.
func (c *Client) GetProgramScope(
	ctx context.Context,
) ([]map[string]any, error) {
	path := fmt.Sprintf(
		"/programs/%s/structured_scopes?page[size]=100",
		url.PathEscape(c.program),
	)

	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	scopes := make([]map[string]any, 0, len(resp.Data))
	for _, r := range resp.Data {
		scope := map[string]any{"id": r.ID}
		for k, v := range r.Attributes {
			scope[k] = v
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func flattenReports(resources []Resource) []Report {
	reports := make([]Report, 0, len(resources))
	for _, r := range resources {
		report := Report{ID: r.ID}
		a := r.Attributes
		if v, ok := a["title"].(string); ok {
			report.Title = v
		}
		if v, ok := a["state"].(string); ok {
			report.State = v
		}
		if v, ok := a["created_at"].(string); ok {
			report.CreatedAt = v
		}
		if v, ok := a["triaged_at"].(string); ok {
			report.TriagedAt = v
		}
		if v, ok := a["vulnerability_information"].(string); ok {
			report.VulnInfo = v
		}
		if v, ok := a["severity_rating"].(string); ok {
			report.Severity = v
		}
		if v, ok := a["weakness"].(string); ok {
			report.WeaknessName = v
		}
		if v, ok := a["bounty_awarded_at"].(string); ok {
			report.BountyAwardedAt = v
		}
		if v, ok := a["impact"].(string); ok {
			report.ImpactDescription = v
		}
		// Reporter username from relationships
		if rel, ok := r.Relationships["reporter"]; ok {
			if data, ok := rel.Data.(map[string]any); ok {
				if attrs, ok := data["attributes"].(map[string]any); ok {
					if u, ok := attrs["username"].(string); ok {
						report.ReporterUsername = u
					}
				}
			}
		}
		reports = append(reports, report)
	}
	return reports
}
