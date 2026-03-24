package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AddSummaryInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Content  string `json:"content" jsonschema:"Summary text describing root cause and remediation"`
}

type AddSummaryOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterAddSummaryTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_add_summary",
		Description: "Add a summary to a HackerOne report. " +
			"Typically used during close-out to document root cause.",
	}, addSummaryHandler(client))
}

func addSummaryHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, AddSummaryInput) (*mcp.CallToolResult, AddSummaryOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input AddSummaryInput,
	) (*mcp.CallToolResult, AddSummaryOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, AddSummaryOutput{}, err
		}
		if input.Content == "" {
			return nil, AddSummaryOutput{},
				fmt.Errorf("content is required")
		}

		err := client.AddSummary(
			ctx, input.ReportID, input.Content,
		)
		if err != nil {
			return nil, AddSummaryOutput{},
				fmt.Errorf(
					"add summary to %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Summary added to report %s", input.ReportID,
		)
		output := AddSummaryOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
