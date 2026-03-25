package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdateTitleInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Title    string `json:"title" jsonschema:"New report title"`
}

type UpdateTitleOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateTitleTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "h1_update_title",
		Description: "Update the title of a HackerOne report.",
	}, updateTitleHandler(client))
}

func updateTitleHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateTitleInput) (*mcp.CallToolResult, UpdateTitleOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateTitleInput,
	) (*mcp.CallToolResult, UpdateTitleOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateTitleOutput{}, err
		}
		if input.Title == "" {
			return nil, UpdateTitleOutput{},
				fmt.Errorf("title is required")
		}

		err := client.UpdateTitle(ctx, input.ReportID, input.Title)
		if err != nil {
			return nil, UpdateTitleOutput{},
				fmt.Errorf(
					"update title on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s title updated", input.ReportID,
		)
		output := UpdateTitleOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
