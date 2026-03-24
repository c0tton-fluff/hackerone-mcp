package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdateStateInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	State    string `json:"state" jsonschema:"New state (triaged/resolved/not-applicable/informative/duplicate/spam)"`
	Message  string `json:"message,omitempty" jsonschema:"Message to include with state change"`
}

type UpdateStateOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateStateTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "h1_update_state",
		Description: "Change the state of a HackerOne report. States: triaged, resolved, not-applicable, informative, duplicate.",
	}, updateStateHandler(client))
}

func updateStateHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateStateInput) (*mcp.CallToolResult, UpdateStateOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateStateInput,
	) (*mcp.CallToolResult, UpdateStateOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateStateOutput{}, err
		}
		err := client.UpdateState(
			ctx, input.ReportID, input.State, input.Message,
		)
		if err != nil {
			return nil, UpdateStateOutput{},
				fmt.Errorf(
					"update state of %s to %s: %w",
					input.ReportID, input.State, err,
				)
		}

		output := UpdateStateOutput{
			Success: true,
			Message: fmt.Sprintf(
				"Report %s state changed to %s",
				input.ReportID, input.State,
			),
		}
		return textResult(output.Message), output, nil
	}
}
