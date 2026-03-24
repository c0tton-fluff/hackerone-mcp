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
	} {
		if kv.val != "" {
			params.Set(kv.key, kv.val)
		}
	}
	for _, id := range f.ReportIDs {
		params.Add("filter[id][]", id)
	}

	firstURL := c.baseURL + "/reports?" + params.Encode()
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
	if !ValidTransitionStates[state] {
		return fmt.Errorf(
			"invalid state %q: must be one of triaged, "+
				"resolved, not-applicable, informative, "+
				"duplicate, spam",
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
		ctx, fmt.Sprintf("/reports/%s/state_change", reportID), body,
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
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/severity", reportID), body,
	)
	return err
}

// AssignReport assigns a report to a user or group by ID.
func (c *Client) AssignReport(
	ctx context.Context, reportID, assigneeID, assigneeType string,
) error {
	if err := ValidateReportID(reportID); err != nil {
		return err
	}
	body := map[string]any{
		"data": map[string]any{
			"type": assigneeType,
			"id":   assigneeID,
		},
	}
	_, err := c.put(
		ctx, fmt.Sprintf("/reports/%s/assignee", reportID), body,
	)
	return err
}

// GetActivities returns the full activity timeline for a report.
func (c *Client) GetActivities(
	ctx context.Context, reportID string,
) ([]Activity, error) {
	if err := ValidateReportID(reportID); err != nil {
		return nil, err
	}

	firstURL := fmt.Sprintf(
		"%s/reports/%s/activities?page[size]=100",
		c.baseURL, reportID,
	)
	resources, err := c.fetchAllPages(ctx, firstURL, 0)
	if err != nil {
		return nil, err
	}

	activities := make([]Activity, 0, len(resources))
	for _, r := range resources {
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
		extractActivityDetails(&act, r.Attributes)
		activities = append(activities, act)
	}
	return activities, nil
}
