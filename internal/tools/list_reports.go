package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validSeverities = map[string]bool{
	"none": true, "low": true, "medium": true, "high": true, "critical": true,
}

var validSorts = map[string]bool{
	"created_at": true, "-created_at": true,
	"severity_rating": true, "-severity_rating": true,
	"bounty_awarded_at": true, "-bounty_awarded_at": true,
	"triaged_at": true, "-triaged_at": true,
}

type ListReportsInput struct {
	Program       string   `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	State         string   `json:"state,omitempty" jsonschema:"Filter by state (new/triaged/resolved/not-applicable/informative/duplicate)"`
	Severity      string   `json:"severity,omitempty" jsonschema:"Filter by severity (none/low/medium/high/critical)"`
	Reporter      string   `json:"reporter,omitempty" jsonschema:"Filter by reporter username"`
	Assignee      string   `json:"assignee,omitempty" jsonschema:"Filter by assignee username"`
	Keyword       string   `json:"keyword,omitempty" jsonschema:"Search reports by keyword in title and vulnerability info"`
	CreatedAfter  string   `json:"created_after,omitempty" jsonschema:"Reports created after this date (YYYY-MM-DD)"`
	CreatedBefore string   `json:"created_before,omitempty" jsonschema:"Reports created before this date (YYYY-MM-DD)"`
	TriagedAfter  string   `json:"triaged_after,omitempty" jsonschema:"Reports triaged after this date (YYYY-MM-DD)"`
	TriagedBefore string   `json:"triaged_before,omitempty" jsonschema:"Reports triaged before this date (YYYY-MM-DD)"`
	ClosedAfter   string   `json:"closed_after,omitempty" jsonschema:"Reports closed after this date (YYYY-MM-DD)"`
	ClosedBefore  string   `json:"closed_before,omitempty" jsonschema:"Reports closed before this date (YYYY-MM-DD)"`
	WeaknessID    string   `json:"weakness_id,omitempty" jsonschema:"Filter by weakness/CWE ID"`
	ReportIDs     []string `json:"report_ids,omitempty" jsonschema:"Fetch specific report IDs (batch lookup)"`
	Sort          string   `json:"sort,omitempty" jsonschema:"Sort field (created_at, -created_at, severity_rating, -severity_rating, bounty_awarded_at, -bounty_awarded_at, triaged_at, -triaged_at). Prefix with - for descending."`
	Limit         int      `json:"limit,omitempty" jsonschema:"Max reports to return (default 25, max 1000). Auto-paginates."`
}

type ListReportsOutput struct {
	Reports []hackerone.Report `json:"reports"`
	Count   int                `json:"count"`
}

func RegisterListReportsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_list_reports",
		Description: fmt.Sprintf(
			"List HackerOne reports. Defaults to program %s. "+
				"Auto-paginates. Filter by state, severity, reporter, "+
				"date range.",
			client.Program(),
		),
	}, listReportsHandler(client))
}

func listReportsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, ListReportsInput) (*mcp.CallToolResult, ListReportsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input ListReportsInput,
	) (*mcp.CallToolResult, ListReportsOutput, error) {
		if input.State != "" && !hackerone.ValidStates[input.State] {
			return nil, ListReportsOutput{},
				fmt.Errorf("invalid state %q", input.State)
		}
		if input.Severity != "" && !validSeverities[input.Severity] {
			return nil, ListReportsOutput{},
				fmt.Errorf("invalid severity %q", input.Severity)
		}
		if input.Sort != "" && !validSorts[input.Sort] {
			return nil, ListReportsOutput{},
				fmt.Errorf("invalid sort %q", input.Sort)
		}
		for _, d := range []struct{ name, val string }{
			{"created_after", input.CreatedAfter},
			{"created_before", input.CreatedBefore},
			{"triaged_after", input.TriagedAfter},
			{"triaged_before", input.TriagedBefore},
			{"closed_after", input.ClosedAfter},
			{"closed_before", input.ClosedBefore},
		} {
			if d.val == "" {
				continue
			}
			if _, err := time.Parse("2006-01-02", d.val); err != nil {
				return nil, ListReportsOutput{},
					fmt.Errorf(
						"invalid %s %q: use YYYY-MM-DD format",
						d.name, d.val,
					)
			}
		}

		reports, err := client.ListReports(ctx, hackerone.ReportFilter{
			Program:       input.Program,
			State:         input.State,
			Severity:      input.Severity,
			Reporter:      input.Reporter,
			Assignee:      input.Assignee,
			Keyword:       input.Keyword,
			CreatedAfter:  input.CreatedAfter,
			CreatedBefore: input.CreatedBefore,
			TriagedAfter:  input.TriagedAfter,
			TriagedBefore: input.TriagedBefore,
			ClosedAfter:   input.ClosedAfter,
			ClosedBefore:  input.ClosedBefore,
			WeaknessID:    input.WeaknessID,
			ReportIDs:     input.ReportIDs,
			Sort:          input.Sort,
			Limit:         input.Limit,
		})
		if err != nil {
			return nil, ListReportsOutput{},
				fmt.Errorf("list reports: %w", err)
		}

		output := ListReportsOutput{
			Reports: reports,
			Count:   len(reports),
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, ListReportsOutput{}, err
		}
		return result, output, nil
	}
}
