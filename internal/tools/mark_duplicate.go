package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type MarkDuplicateInput struct {
	ReportID   string `json:"report_id" jsonschema:"Report ID to mark as duplicate"`
	OriginalID string `json:"original_report_id" jsonschema:"ID of the original report this duplicates"`
}

type MarkDuplicateOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterMarkDuplicateTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_mark_duplicate",
		Description: "Mark a HackerOne report as a duplicate of " +
			"another report. Links the two reports in H1.",
	}, markDuplicateHandler(client))
}

func markDuplicateHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, MarkDuplicateInput) (*mcp.CallToolResult, MarkDuplicateOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input MarkDuplicateInput,
	) (*mcp.CallToolResult, MarkDuplicateOutput, error) {
		err := client.MarkDuplicate(
			ctx, input.ReportID, input.OriginalID,
		)
		if err != nil {
			return nil, MarkDuplicateOutput{},
				fmt.Errorf(
					"mark %s as duplicate of %s: %w",
					input.ReportID, input.OriginalID, err,
				)
		}

		output := MarkDuplicateOutput{
			Success: true,
			Message: fmt.Sprintf(
				"Report %s marked as duplicate of %s",
				input.ReportID, input.OriginalID,
			),
		}
		return textResult(output.Message), output, nil
	}
}
