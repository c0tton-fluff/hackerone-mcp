package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

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

	params := url.Values{}
	params.Set("filter[program][]", program)
	params.Set("page[size]", strconv.Itoa(min(limit, 100)))
	for _, kv := range []struct{ key, val string }{
		{"filter[state][]", f.State},
		{"filter[severity][]", f.Severity},
		{"filter[reporter][]", f.Reporter},
		{"filter[created_at__gt]", f.CreatedAfter},
		{"filter[created_at__lt]", f.CreatedBefore},
		{"filter[triaged_at__gt]", f.TriagedAfter},
		{"filter[triaged_at__lt]", f.TriagedBefore},
		{"filter[closed_at__gt]", f.ClosedAfter},
		{"filter[closed_at__lt]", f.ClosedBefore},
		{"filter[assignee][]", f.Assignee},
		{"filter[keyword]", f.Keyword},
		{"filter[weakness_id][]", f.WeaknessID},
		{"sort", f.Sort},
		{"order", f.SortDirection},
	} {
		if kv.val != "" {
			params.Set(kv.key, kv.val)
		}
	}
	for _, id := range f.ReportIDs {
		params.Add("filter[id][]", id)
	}

	reportsPath := "/reports"
	if c.hacker {
		reportsPath = "/hackers/me/reports"
	}
	firstURL := c.baseURL + reportsPath + "?" + params.Encode()
	resources, err := c.fetchAllPages(ctx, firstURL, limit)
	if err != nil {
		return nil, err
	}

	reports := flattenReports(resources)
	if reports == nil {
		reports = []Report{}
	}
	return reports, nil
}

// GetReportAttachments returns just the attachment metadata for a report.
func (c *Client) GetReportAttachments(
	ctx context.Context, reportID string,
) ([]Attachment, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}
	raw, err := c.get(ctx, c.reportPath(reportID))
	if err != nil {
		return nil, err
	}
	var resp SingleResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return extractAttachments(resp.Data), nil
}

// GetReport returns a single report by ID.
func (c *Client) GetReport(
	ctx context.Context, reportID string,
) (*Report, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}

	raw, err := c.get(ctx, c.reportPath(reportID))
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
	if !ValidTransitionStates[state] {
		return fmt.Errorf(
			"invalid state %q: must be one of triaged, "+
				"needs-more-info, resolved, not-applicable, "+
				"informative, duplicate, spam, "+
				"pending-program-review",
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
		ctx, fmt.Sprintf("/reports/%s/state_changes", reportID), body,
	)
	return err
}

// MaxBountyAmount is the upper bound for a single bounty award.
const MaxBountyAmount = 50000.0

// AwardBounty grants a bounty on a report.
func (c *Client) AwardBounty(
	ctx context.Context, reportID string,
	amount float64, message string,
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
		ctx, fmt.Sprintf("/reports/%s/state_changes", reportID), body,
	)
	return err
}

// UpdateSeverity sets the severity rating and optional CVSS vector on a report.
func (c *Client) UpdateSeverity(
	ctx context.Context, reportID, rating, cvssVector string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	attrs := map[string]any{"rating": rating}
	if cvssVector != "" {
		attrs["cvss_vector_string"] = cvssVector
	}
	body := map[string]any{
		"data": map[string]any{
			"type":       "severity",
			"attributes": attrs,
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/severities", reportID), body,
	)
	return err
}

// AssignReport assigns a report to a user by username.
func (c *Client) AssignReport(
	ctx context.Context, reportID, username string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "assignee",
			"attributes": map[string]any{
				"username": username,
			},
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/assignee", reportID), body,
	)
	return err
}

// UnassignReport clears the assignee on a report.
func (c *Client) UnassignReport(
	ctx context.Context, reportID string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "nobody",
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/assignee", reportID), body,
	)
	return err
}

// UpdateTitle changes the title of a report.
func (c *Client) UpdateTitle(
	ctx context.Context, reportID, title string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "title",
			"attributes": map[string]any{
				"title": title,
			},
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/title", reportID), body,
	)
	return err
}

// UpdateWeakness sets the CWE/weakness on a report.
func (c *Client) UpdateWeakness(
	ctx context.Context, reportID, weaknessID string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "weakness",
			"attributes": map[string]any{
				"weakness_id": weaknessID,
			},
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/weakness", reportID), body,
	)
	return err
}

// UpdateTags sets the tags on a report (replaces all existing tags).
func (c *Client) UpdateTags(
	ctx context.Context, reportID string, tagNames []string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "report-tag",
			"attributes": map[string]any{
				"tag_names": tagNames,
			},
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/report_tags", reportID), body,
	)
	return err
}

// RequestDisclosure posts a disclosure request on a report.
func (c *Client) RequestDisclosure(
	ctx context.Context, reportID, substate string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "disclosure-request",
			"attributes": map[string]any{
				"substate": substate,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/disclosure_requests", reportID), body,
	)
	return err
}

// parseActivities converts JSON:API resources into Activity structs.
func parseActivities(resources []Resource) []Activity {
	activities := make([]Activity, 0, len(resources))
	for _, r := range resources {
		act := Activity{
			ID:          r.ID,
			Type:        r.Type,
			DisplayName: activityDisplayName(r.Type),
		}
		act.Message, _ = r.Attributes["message"].(string)
		act.Internal, _ = r.Attributes["internal"].(bool)
		act.CreatedAt, _ = r.Attributes["created_at"].(string)
		if actor := relAttrs(r, "actor"); actor != nil {
			act.Actor, _ = actor["username"].(string)
		}
		extractActivityDetails(&act, r.Attributes)
		activities = append(activities, act)
	}
	return activities
}

// IncrementalActivities polls for new activities across all reports.
func (c *Client) IncrementalActivities(
	ctx context.Context, handle, updatedAfter string, limit int,
) ([]Activity, error) {
	if limit <= 0 {
		limit = 25
	}
	params := url.Values{}
	if handle != "" {
		params.Set("handle", handle)
	} else {
		params.Set("handle", c.program)
	}
	if updatedAfter != "" {
		params.Set("updated_at_after", updatedAfter)
	}
	params.Set("page[size]", strconv.Itoa(min(limit, 100)))

	firstURL := c.baseURL + "/incremental/activities?" + params.Encode()
	resources, err := c.fetchAllPages(ctx, firstURL, limit)
	if err != nil {
		return nil, err
	}

	return parseActivities(resources), nil
}

// GetActivities returns the full activity timeline for a report
// using the documented incremental activities endpoint.
func (c *Client) GetActivities(
	ctx context.Context, reportID string,
) ([]Activity, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Set("report_id", reportID)
	params.Set("page[size]", "100")

	firstURL := c.baseURL + "/incremental/activities?" + params.Encode()
	resources, err := c.fetchAllPages(ctx, firstURL, 0)
	if err != nil {
		return nil, err
	}

	return parseActivities(resources), nil
}

// AddSummary posts a summary on a report.
func (c *Client) AddSummary(
	ctx context.Context, reportID, content string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "summary",
			"attributes": map[string]any{
				"content": content,
			},
		},
	}
	_, err := c.post(
		ctx, fmt.Sprintf("/reports/%s/summaries", reportID), body,
	)
	return err
}

// UpdateCVEs sets CVE IDs on a report.
func (c *Client) UpdateCVEs(
	ctx context.Context, reportID string, cveIDs []string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": "cve",
			"attributes": map[string]any{
				"cve_ids": cveIDs,
			},
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/cves", reportID), body,
	)
	return err
}

// CloseComments locks comments on a report.
func (c *Client) CloseComments(
	ctx context.Context, reportID string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/close_comments", reportID),
		map[string]any{},
	)
	return err
}

var validRetestActions = map[string]bool{
	"request": true, "approve": true, "reject": true, "cancel": true,
}

// ManageRetest handles retest lifecycle (request/approve/reject/cancel).
func (c *Client) ManageRetest(
	ctx context.Context, reportID, action, summary string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	if !validRetestActions[action] {
		return fmt.Errorf(
			"invalid retest action %q: must be request, approve, reject, or cancel",
			action,
		)
	}

	base := fmt.Sprintf("/reports/%s/retests", reportID)

	switch action {
	case "request":
		body := map[string]any{
			"data": map[string]any{
				"type": "retest-request",
				"attributes": map[string]any{
					"summary": summary,
				},
			},
		}
		_, err := c.post(ctx, base, body)
		return err
	case "approve":
		_, err := c.post(ctx, base+"/approve", map[string]any{})
		return err
	case "reject":
		_, err := c.post(ctx, base+"/reject", map[string]any{})
		return err
	case "cancel":
		_, err := c.delete(ctx, base+"/cancel")
		return err
	}
	return nil
}

// CreateReport creates a new report and returns its ID.
func (c *Client) CreateReport(
	ctx context.Context, p CreateReportParams,
) (string, error) {
	handle := c.resolveProgram(p.Program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return "", err
	}

	attrs := map[string]any{
		"title":                     p.Title,
		"vulnerability_information": p.VulnInfo,
		"severity_rating":           p.Severity,
	}
	if p.WeaknessID != "" {
		attrs["weakness_id"] = p.WeaknessID
	}

	rels := map[string]any{
		"program": map[string]any{
			"data": map[string]any{
				"type": "program",
				"id":   programID,
			},
		},
	}
	if p.ScopeID != "" {
		rels["structured_scope"] = map[string]any{
			"data": map[string]any{
				"type": "structured-scope",
				"id":   p.ScopeID,
			},
		}
	}

	body := map[string]any{
		"data": map[string]any{
			"type":          "report",
			"attributes":    attrs,
			"relationships": rels,
		},
	}

	createPath := "/reports"
	if c.hacker {
		createPath = "/hackers/reports"
	}
	raw, err := c.post(ctx, createPath, body)
	if err != nil {
		return "", err
	}

	var resp SingleResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("parse create report response: %w", err)
	}
	return resp.Data.ID, nil
}
