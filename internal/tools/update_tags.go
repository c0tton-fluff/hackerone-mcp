package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdateTagsInput struct {
	ReportID string   `json:"report_id" jsonschema:"HackerOne report ID"`
	TagNames []string `json:"tag_names" jsonschema:"List of tag names to set on the report (replaces all existing tags)"`
}

type UpdateTagsOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateTagsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_update_tags",
		Description: "Set tags on a HackerOne report. " +
			"Replaces all existing tags with the provided list.",
	}, updateTagsHandler(client))
}

func updateTagsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateTagsInput) (*mcp.CallToolResult, UpdateTagsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateTagsInput,
	) (*mcp.CallToolResult, UpdateTagsOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateTagsOutput{}, err
		}
		if len(input.TagNames) == 0 {
			return nil, UpdateTagsOutput{},
				fmt.Errorf("tag_names is required (non-empty list)")
		}

		err := client.UpdateTags(
			ctx, input.ReportID, input.TagNames,
		)
		if err != nil {
			return nil, UpdateTagsOutput{},
				fmt.Errorf(
					"update tags on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s tags set to [%s]",
			input.ReportID, strings.Join(input.TagNames, ", "),
		)
		output := UpdateTagsOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
