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

type ListReportsInput struct {
	Program       string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	State         string `json:"state,omitempty" jsonschema:"Filter by state (new/triaged/resolved/not-applicable/informative/duplicate)"`
	Severity      string `json:"severity,omitempty" jsonschema:"Filter by severity (none/low/medium/high/critical)"`
	Reporter      string `json:"reporter,omitempty" jsonschema:"Filter by reporter username"`
	Assignee      string `json:"assignee,omitempty" jsonschema:"Filter by assignee username"`
	CreatedAfter  string `json:"created_after,omitempty" jsonschema:"Reports created after this date (ISO 8601, e.g. 2024-01-01)"`
	CreatedBefore string `json:"created_before,omitempty" jsonschema:"Reports created before this date (ISO 8601)"`
	Sort          string `json:"sort,omitempty" jsonschema:"Sort field (created_at, -created_at, severity_rating, -severity_rating, bounty_awarded_at, -bounty_awarded_at). Prefix with - for descending."`
	Limit         int    `json:"limit,omitempty" jsonschema:"Max reports to return (default 25, max 1000). Auto-paginates."`
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
		for _, d := range []struct{ name, val string }{
			{"created_after", input.CreatedAfter},
			{"created_before", input.CreatedBefore},
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
			CreatedAfter:  input.CreatedAfter,
			CreatedBefore: input.CreatedBefore,
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
