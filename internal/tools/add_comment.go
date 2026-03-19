package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AddCommentInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Message  string `json:"message" jsonschema:"Comment text"`
	Internal bool   `json:"internal,omitempty" jsonschema:"If true the comment is only visible to the team (default false)"`
}

type AddCommentOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterAddCommentTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "h1_add_comment",
		Description: "Add a comment to a HackerOne report. Use internal=true for team-only notes.",
	}, addCommentHandler(client))
}

func addCommentHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, AddCommentInput) (*mcp.CallToolResult, AddCommentOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input AddCommentInput,
	) (*mcp.CallToolResult, AddCommentOutput, error) {
		if input.ReportID == "" || input.Message == "" {
			return nil, AddCommentOutput{},
				fmt.Errorf("report_id and message are required")
		}

		err := client.AddComment(
			ctx, input.ReportID, input.Message, input.Internal,
		)
		if err != nil {
			return nil, AddCommentOutput{},
				fmt.Errorf("add comment to %s: %w", input.ReportID, err)
		}

		vis := "public"
		if input.Internal {
			vis = "internal"
		}
		output := AddCommentOutput{
			Success: true,
			Message: fmt.Sprintf(
				"Added %s comment to report %s",
				vis, input.ReportID,
			),
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: output.Message},
			},
		}, output, nil
	}
}
