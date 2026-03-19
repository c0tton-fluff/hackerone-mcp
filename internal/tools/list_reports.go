package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validListStates = map[string]bool{
	"new": true, "triaged": true, "resolved": true,
	"not-applicable": true, "informative": true, "duplicate": true, "spam": true,
}

var validSeverities = map[string]bool{
	"none": true, "low": true, "medium": true, "high": true, "critical": true,
}

type ListReportsInput struct {
	State    string `json:"state,omitempty" jsonschema:"Filter by state (new/triaged/resolved/not-applicable/informative/duplicate)"`
	Severity string `json:"severity,omitempty" jsonschema:"Filter by severity (none/low/medium/high/critical)"`
	Limit    int    `json:"limit,omitempty" jsonschema:"Max reports to return (default 25 max 100)"`
}

type ListReportsOutput struct {
	Reports []hackerone.Report `json:"reports"`
	Count   int               `json:"count"`
}

func RegisterListReportsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_list_reports",
		Description: fmt.Sprintf(
			"List HackerOne reports for program %s. "+
				"Filter by state and severity. Returns id/title/state/severity/created_at.",
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
		if input.State != "" && !validListStates[input.State] {
			return nil, ListReportsOutput{},
				fmt.Errorf("invalid state %q", input.State)
		}
		if input.Severity != "" && !validSeverities[input.Severity] {
			return nil, ListReportsOutput{},
				fmt.Errorf("invalid severity %q", input.Severity)
		}

		limit := input.Limit
		if limit <= 0 || limit > 100 {
			limit = 25
		}

		reports, err := client.ListReports(
			ctx, input.State, input.Severity, limit,
		)
		if err != nil {
			return nil, ListReportsOutput{},
				fmt.Errorf("list reports: %w", err)
		}

		output := ListReportsOutput{
			Reports: reports,
			Count:   len(reports),
		}

		text, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, ListReportsOutput{}, fmt.Errorf("marshal output: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(text)},
			},
		}, output, nil
	}
}
