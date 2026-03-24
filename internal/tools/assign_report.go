package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AssignReportInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Username string `json:"username" jsonschema:"Username to assign the report to. Use h1_list_members to find usernames."`
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
		Description: "Assign a HackerOne report to a user by username. " +
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
		if input.Username == "" {
			return nil, AssignReportOutput{},
				fmt.Errorf("username is required")
		}

		err := client.AssignReport(
			ctx, input.ReportID, input.Username,
		)
		if err != nil {
			return nil, AssignReportOutput{},
				fmt.Errorf(
					"assign report %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s assigned to %s",
			input.ReportID, input.Username,
		)
		output := AssignReportOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
