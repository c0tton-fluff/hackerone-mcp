package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AssignReportInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Username string `json:"username,omitempty" jsonschema:"Username to assign. Use h1_list_members to find usernames. Omit for group assignment or 'nobody' to clear."`
	GroupID  string `json:"group_id,omitempty" jsonschema:"Numeric group ID to assign. Use instead of username for group assignment."`
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
		Description: "Assign a HackerOne report to a user (by username), " +
			"a group (by group_id), or clear the assignee (username='nobody' or omit both). " +
			"Use h1_list_members to find usernames.",
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

		var msg string
		var err error

		switch {
		case input.GroupID != "":
			err = client.AssignReportToGroup(ctx, input.ReportID, input.GroupID)
			msg = fmt.Sprintf("Report %s assigned to group %s", input.ReportID, input.GroupID)
		case input.Username == "" || input.Username == "nobody":
			err = client.UnassignReport(ctx, input.ReportID)
			msg = fmt.Sprintf("Report %s assignee cleared", input.ReportID)
		default:
			err = client.AssignReport(ctx, input.ReportID, input.Username)
			msg = fmt.Sprintf("Report %s assigned to %s", input.ReportID, input.Username)
		}

		if err != nil {
			return nil, AssignReportOutput{},
				fmt.Errorf("assign report %s: %w", input.ReportID, err)
		}
		output := AssignReportOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
