package hackerone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var validReportID = regexp.MustCompile(`^\d+$`)

const (
	baseURL    = "https://api.hackerone.com/v1"
	maxRetries = 3
	maxReports = 1000
)

type Client struct {
	http         *http.Client
	apiID        string
	apiKey       string
	program      string
	programCache []Program
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

func ValidateReportID(id string) error {
	if !validReportID.MatchString(id) {
		return fmt.Errorf("invalid report ID %q: must be numeric", id)
	}
	return nil
}

func (c *Client) resolveProgram(handle string) string {
	if handle != "" {
		return handle
	}
	return c.program
}

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, baseURL+path, nil)
}

func (c *Client) getURL(ctx context.Context, fullURL string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, fullURL, nil)
}

func (c *Client) post(ctx context.Context, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	return c.do(ctx, http.MethodPost, baseURL+path, payload)
}

// do executes an HTTP request with automatic retry on 429 rate limits.
func (c *Client) do(
	ctx context.Context, method, reqURL string, body []byte,
) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, retryAfter, err := c.doOnce(ctx, method, reqURL, body)
		if err == nil {
			return data, nil
		}
		if retryAfter == 0 || attempt >= maxRetries {
			return nil, err
		}
		backoff := max(retryAfter, time.Duration(1<<uint(attempt))*time.Second)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// doOnce executes a single HTTP request. Returns retryAfter > 0 on 429.
func (c *Client) doOnce(
	ctx context.Context, method, reqURL string, body []byte,
) ([]byte, time.Duration, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.SetBasicAuth(c.apiID, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request %s %s: %w", method, reqURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := parseRetryAfter(resp.Header)
		return nil, wait, fmt.Errorf("rate limited (429)")
	}

	if resp.StatusCode >= 400 {
		snippet := string(data)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return nil, 0, fmt.Errorf(
			"%s %s returned %d: %s",
			method, reqURL, resp.StatusCode, snippet,
		)
	}

	return data, 0, nil
}

func parseRetryAfter(h http.Header) time.Duration {
	val := h.Get("Retry-After")
	if val == "" {
		return 2 * time.Second
	}
	var wait time.Duration
	if secs, err := strconv.Atoi(val); err == nil {
		wait = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(val); err == nil {
		wait = time.Until(t)
	}
	if wait <= 0 {
		wait = 2 * time.Second
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	return wait
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

// ListReports returns reports with filtering and auto-pagination.
func (c *Client) ListReports(
	ctx context.Context, f ReportFilter,
) ([]Report, error) {
	program := c.resolveProgram(f.Program)
	limit := f.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > maxReports {
		limit = maxReports
	}

	pageSize := min(limit, 100)
	nextURL := fmt.Sprintf(
		"%s/reports?filter[program][]=%s&page[size]=%d",
		baseURL, url.QueryEscape(program), pageSize,
	)
	if f.State != "" {
		nextURL += "&filter[state][]=" + url.QueryEscape(f.State)
	}
	if f.Severity != "" {
		nextURL += "&filter[severity][]=" + url.QueryEscape(f.Severity)
	}
	if f.Reporter != "" {
		nextURL += "&filter[reporter][]=" + url.QueryEscape(f.Reporter)
	}
	if f.CreatedAfter != "" {
		nextURL += "&filter[created_at__gt]=" + url.QueryEscape(f.CreatedAfter)
	}
	if f.CreatedBefore != "" {
		nextURL += "&filter[created_at__lt]=" + url.QueryEscape(f.CreatedBefore)
	}
	if f.Assignee != "" {
		nextURL += "&filter[assignee][]=" + url.QueryEscape(f.Assignee)
	}
	if f.Keyword != "" {
		nextURL += "&filter[keyword]=" + url.QueryEscape(f.Keyword)
	}
	if f.Sort != "" {
		nextURL += "&sort=" + url.QueryEscape(f.Sort)
	}

	var all []Report
	for nextURL != "" && len(all) < limit {
		if !strings.HasPrefix(nextURL, baseURL) {
			return nil, fmt.Errorf(
				"pagination URL not under API base: %s", nextURL,
			)
		}
		raw, err := c.getURL(ctx, nextURL)
		if err != nil {
			return nil, err
		}

		var resp ListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}

		all = append(all, flattenReports(resp.Data)...)
		nextURL = resp.Links.Next
	}

	if len(all) > limit {
		all = all[:limit]
	}
	if all == nil {
		all = []Report{}
	}
	return all, nil
}

// GetReport returns a single report by ID.
func (c *Client) GetReport(
	ctx context.Context, reportID string,
) (*Report, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}

	raw, err := c.get(ctx, fmt.Sprintf("/reports/%s", reportID))
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
	ctx context.Context, reportID, message string, internal bool,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "activity-comment",
			"attributes": map[string]any{
				"message":  message,
				"internal": internal,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/activities", reportID), body,
	)
	return err
}

// UpdateState changes report state (e.g. triaged, resolved).
func (c *Client) UpdateState(
	ctx context.Context, reportID, state, message string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if !ValidStates[state] {
		return fmt.Errorf(
			"invalid state %q: must be one of new, triaged, resolved, "+
				"not-applicable, informative, duplicate, spam",
			state,
		)
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "state-change",
			"attributes": map[string]any{
				"state":   state,
				"message": message,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/state_change", reportID), body,
	)
	return err
}

// MaxBountyAmount is the upper bound for a single bounty award.
const MaxBountyAmount = 50000.0

// AwardBounty grants a bounty on a report.
func (c *Client) AwardBounty(
	ctx context.Context, reportID string, amount float64, message string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if amount > MaxBountyAmount {
		return fmt.Errorf(
			"bounty amount $%.2f exceeds maximum $%.2f",
			amount, MaxBountyAmount,
		)
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "bounty",
			"attributes": map[string]any{
				"amount":  amount,
				"message": message,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/bounties", reportID), body,
	)
	return err
}

// cachedPrograms fetches and caches the program list (one API call per session).
func (c *Client) cachedPrograms(ctx context.Context) ([]Program, error) {
	if c.programCache != nil {
		return c.programCache, nil
	}

	raw, err := c.get(ctx, "/me/programs?page[size]=100")
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	programs := make([]Program, 0, len(resp.Data))
	for _, r := range resp.Data {
		p := Program{ID: r.ID}
		if h, ok := r.Attributes["handle"].(string); ok {
			p.Handle = h
		}
		programs = append(programs, p)
	}
	c.programCache = programs
	return programs, nil
}

// ListPrograms returns all programs accessible to the API token.
func (c *Client) ListPrograms(ctx context.Context) ([]Program, error) {
	return c.cachedPrograms(ctx)
}

// getProgramID resolves a program handle to its numeric ID.
func (c *Client) getProgramID(
	ctx context.Context, handle string,
) (string, error) {
	programs, err := c.cachedPrograms(ctx)
	if err != nil {
		return "", fmt.Errorf("lookup program ID: %w", err)
	}

	for _, p := range programs {
		if p.Handle == handle {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf(
		"program %q not found in accessible programs", handle,
	)
}

// GetProgramScope returns structured scopes for a program.
func (c *Client) GetProgramScope(
	ctx context.Context, program string,
) ([]map[string]any, error) {
	handle := c.resolveProgram(program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf(
		"/programs/%s/structured_scopes?page[size]=100",
		url.PathEscape(programID),
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
		maps.Copy(scope, r.Attributes)
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// GetActivities returns the activity timeline for a report.
func (c *Client) GetActivities(
	ctx context.Context, reportID string,
) ([]Activity, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}

	path := fmt.Sprintf(
		"/reports/%s/activities?page[size]=100", reportID,
	)
	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse activities: %w", err)
	}

	activities := make([]Activity, 0, len(resp.Data))
	for _, r := range resp.Data {
		act := Activity{
			ID:   r.ID,
			Type: r.Type,
		}
		act.Message, _ = r.Attributes["message"].(string)
		act.Internal, _ = r.Attributes["internal"].(bool)
		act.CreatedAt, _ = r.Attributes["created_at"].(string)
		if actor := relAttrs(r, "actor"); actor != nil {
			act.Actor, _ = actor["username"].(string)
		}
		activities = append(activities, act)
	}
	return activities, nil
}

// MarkDuplicate changes a report to duplicate state linking to the original.
func (c *Client) MarkDuplicate(
	ctx context.Context, reportID, originalID string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if err := ValidateReportID(originalID); err != nil {
		return fmt.Errorf("invalid original report ID: %w", err)
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "state-change",
			"attributes": map[string]any{
				"state":              "duplicate",
				"original_report_id": originalID,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/state_change", reportID), body,
	)
	return err
}

// GetProgramPolicy returns the policy body for a program.
func (c *Client) GetProgramPolicy(
	ctx context.Context, program string,
) (string, error) {
	handle := c.resolveProgram(program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return "", err
	}

	raw, err := c.get(ctx, fmt.Sprintf("/programs/%s", programID))
	if err != nil {
		return "", err
	}

	var resp SingleResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("parse program response: %w", err)
	}

	policy, _ := resp.Data.Attributes["policy"].(string)
	return policy, nil
}

// parseCvssVector parses a CVSS 3.x vector string into components.
func parseCvssVector(vector string) *CvssMetrics {
	if vector == "" {
		return nil
	}

	labels := map[string]map[string]string{
		"AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
		"AC": {"L": "Low", "H": "High"},
		"PR": {"N": "None", "L": "Low", "H": "High"},
		"UI": {"N": "None", "R": "Required"},
		"S":  {"U": "Unchanged", "C": "Changed"},
		"C":  {"N": "None", "L": "Low", "H": "High"},
		"I":  {"N": "None", "L": "Low", "H": "High"},
		"A":  {"N": "None", "L": "Low", "H": "High"},
	}

	vals := make(map[string]string)
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			key := kv[0]
			if m, ok := labels[key]; ok {
				if label, ok := m[kv[1]]; ok {
					vals[key] = label
				} else {
					vals[key] = kv[1]
				}
			}
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

func flattenReports(resources []Resource) []Report {
	reports := make([]Report, 0, len(resources))
	for _, r := range resources {
		report := Report{ID: r.ID}
		a := r.Attributes

		report.Title, _ = a["title"].(string)
		report.State, _ = a["state"].(string)
		report.CreatedAt, _ = a["created_at"].(string)
		report.TriagedAt, _ = a["triaged_at"].(string)
		report.ClosedAt, _ = a["closed_at"].(string)
		report.BountyAwardedAt, _ = a["bounty_awarded_at"].(string)
		report.VulnInfo, _ = a["vulnerability_information"].(string)
		report.ImpactDescription, _ = a["impact"].(string)

		if sev := relAttrs(r, "severity"); sev != nil {
			report.Severity, _ = sev["rating"].(string)
			if score, ok := sev["score"].(float64); ok {
				report.CvssScore = score
			}
			report.CvssVector, _ = sev["cvss_vector_string"].(string)
		}
		report.CvssBreakdown = parseCvssVector(report.CvssVector)
		if report.Severity == "" {
			report.Severity, _ = a["severity_rating"].(string)
		}

		if weak := relAttrs(r, "weakness"); weak != nil {
			report.WeaknessName, _ = weak["name"].(string)
			report.CweID, _ = weak["external_id"].(string)
		}

		if rep := relAttrs(r, "reporter"); rep != nil {
			report.ReporterUsername, _ = rep["username"].(string)
		}

		if assignee := relAttrs(r, "assignee"); assignee != nil {
			report.Assignee, _ = assignee["username"].(string)
		}

		if prog := relAttrs(r, "program"); prog != nil {
			report.ProgramHandle, _ = prog["handle"].(string)
		}

		if scope := relAttrs(r, "structured_scope"); scope != nil {
			report.AssetIdentifier, _ = scope["asset_identifier"].(string)
		}

		report.BountyAmount = sumBounties(r)

		reports = append(reports, report)
	}
	return reports
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
