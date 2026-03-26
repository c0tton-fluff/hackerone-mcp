package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validSeverities = map[string]bool{
	"none": true, "low": true, "medium": true, "high": true, "critical": true,
}

var validSortFields = map[string]bool{
	"created_at": true, "severity_rating": true,
	"bounty_awarded_at": true, "triaged_at": true,
}

type ListReportsInput struct {
	Program       string   `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	State         string   `json:"state,omitempty" jsonschema:"Filter by state, comma-separated (new,triaged,resolved,not-applicable,informative,duplicate,spam)"`
	Severity      string   `json:"severity,omitempty" jsonschema:"Filter by severity, comma-separated (none,low,medium,high,critical)"`
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
	Sort          string   `json:"sort,omitempty" jsonschema:"Sort field (created_at, severity_rating, bounty_awarded_at, triaged_at). Prefix with - for descending (e.g. -created_at)."`
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
		for s := range strings.SplitSeq(input.State, ",") {
			if s = strings.TrimSpace(s); s != "" && !hackerone.ValidStates[s] {
				return nil, ListReportsOutput{},
					fmt.Errorf("invalid state %q", s)
			}
		}
		for s := range strings.SplitSeq(input.Severity, ",") {
			if s = strings.TrimSpace(s); s != "" && !validSeverities[s] {
				return nil, ListReportsOutput{},
					fmt.Errorf("invalid severity %q", s)
			}
		}
		var sortField, sortDir string
		if input.Sort != "" {
			s := input.Sort
			if strings.HasPrefix(s, "-") {
				sortDir = "desc"
				s = s[1:]
			} else {
				sortDir = "asc"
			}
			if !validSortFields[s] {
				return nil, ListReportsOutput{},
					fmt.Errorf("invalid sort %q", input.Sort)
			}
			sortField = s
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
			Sort:          sortField,
			SortDirection: sortDir,
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
