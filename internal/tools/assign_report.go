package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validAssigneeTypes = map[string]bool{
	"user": true, "group": true,
}

type AssignReportInput struct {
	ReportID     string `json:"report_id" jsonschema:"HackerOne report ID"`
	AssigneeID   string `json:"assignee_id" jsonschema:"User or group ID to assign"`
	AssigneeType string `json:"assignee_type" jsonschema:"Type of assignee: user or group"`
}

type AssignReportOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterAssignReportTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_assign_report",
		Description: "Assign a HackerOne report to a user or group. " +
			"Use h1_list_members to find user/group IDs.",
	}, assignReportHandler(client))
}

func assignReportHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, AssignReportInput) (*mcp.CallToolResult, AssignReportOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input AssignReportInput,
	) (*mcp.CallToolResult, AssignReportOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, AssignReportOutput{}, err
		}
		if input.AssigneeID == "" {
			return nil, AssignReportOutput{},
				fmt.Errorf("assignee_id is required")
		}
		if !validAssigneeTypes[input.AssigneeType] {
			return nil, AssignReportOutput{},
				fmt.Errorf(
					"invalid assignee_type %q: must be user or group",
					input.AssigneeType,
				)
		}

		err := client.AssignReport(
			ctx, input.ReportID,
			input.AssigneeID, input.AssigneeType,
		)
		if err != nil {
			return nil, AssignReportOutput{},
				fmt.Errorf(
					"assign report %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s assigned to %s %s",
			input.ReportID, input.AssigneeType, input.AssigneeID,
		)
		output := AssignReportOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
