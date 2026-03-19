package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetReportInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
}

type GetReportOutput struct {
	Report *hackerone.Report `json:"report"`
}

func RegisterGetReportTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "h1_get_report",
		Description: "Get full details of a HackerOne report by ID. Returns title, state, severity, vulnerability info, reporter, and timeline.",
	}, getReportHandler(client))
}

func getReportHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, GetReportInput) (*mcp.CallToolResult, GetReportOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input GetReportInput,
	) (*mcp.CallToolResult, GetReportOutput, error) {
		if input.ReportID == "" {
			return nil, GetReportOutput{},
				fmt.Errorf("report_id is required")
		}

		report, err := client.GetReport(ctx, input.ReportID)
		if err != nil {
			return nil, GetReportOutput{},
				fmt.Errorf("get report %s: %w", input.ReportID, err)
		}

		output := GetReportOutput{Report: report}
		text, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, GetReportOutput{}, fmt.Errorf("marshal output: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(text)},
			},
		}, output, nil
	}
}
