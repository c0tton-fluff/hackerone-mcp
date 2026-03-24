package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validRetestToolActions = map[string]bool{
	"request": true, "approve": true, "reject": true, "cancel": true,
}

type ManageRetestInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Action   string `json:"action" jsonschema:"Retest action: request, approve, reject, or cancel"`
	Summary  string `json:"summary,omitempty" jsonschema:"Summary of what to verify (required for request action)"`
}

type ManageRetestOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterManageRetestTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_manage_retest",
		Description: "Manage retests on a HackerOne report. " +
			"Actions: request (needs summary), approve, reject, cancel.",
	}, manageRetestHandler(client))
}

func manageRetestHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, ManageRetestInput) (*mcp.CallToolResult, ManageRetestOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input ManageRetestInput,
	) (*mcp.CallToolResult, ManageRetestOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, ManageRetestOutput{}, err
		}
		if !validRetestToolActions[input.Action] {
			return nil, ManageRetestOutput{},
				fmt.Errorf(
					"invalid action %q: must be request, approve, reject, or cancel",
					input.Action,
				)
		}
		if input.Action == "request" && input.Summary == "" {
			return nil, ManageRetestOutput{},
				fmt.Errorf("summary is required for request action")
		}

		err := client.ManageRetest(
			ctx, input.ReportID, input.Action, input.Summary,
		)
		if err != nil {
			return nil, ManageRetestOutput{},
				fmt.Errorf(
					"retest %s on %s: %w",
					input.Action, input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Retest %s on report %s",
			input.Action, input.ReportID,
		)
		output := ManageRetestOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
