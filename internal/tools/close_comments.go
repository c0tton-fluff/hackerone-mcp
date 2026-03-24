package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CloseCommentsInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
}

type CloseCommentsOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterCloseCommentsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_close_comments",
		Description: "Lock comments on a HackerOne report. " +
			"Prevents further comments from reporter and team.",
	}, closeCommentsHandler(client))
}

func closeCommentsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, CloseCommentsInput) (*mcp.CallToolResult, CloseCommentsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input CloseCommentsInput,
	) (*mcp.CallToolResult, CloseCommentsOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, CloseCommentsOutput{}, err
		}

		err := client.CloseComments(ctx, input.ReportID)
		if err != nil {
			return nil, CloseCommentsOutput{},
				fmt.Errorf(
					"close comments on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Comments closed on report %s", input.ReportID,
		)
		output := CloseCommentsOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
