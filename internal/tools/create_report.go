package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CreateReportInput struct {
	Program    string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	Title      string `json:"title" jsonschema:"Report title"`
	VulnInfo   string `json:"vulnerability_information" jsonschema:"Vulnerability description with steps to reproduce"`
	Severity   string `json:"severity_rating" jsonschema:"Severity rating (none/low/medium/high/critical)"`
	WeaknessID string `json:"weakness_id,omitempty" jsonschema:"H1 weakness ID (optional)"`
	ScopeID    string `json:"structured_scope_id,omitempty" jsonschema:"Structured scope ID (optional, from h1_get_scope)"`
}

type CreateReportOutput struct {
	Success  bool   `json:"success"`
	ReportID string `json:"report_id"`
	Message  string `json:"message"`
}

func RegisterCreateReportTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_create_report",
		Description: fmt.Sprintf(
			"Create a new HackerOne report. Defaults to program %s.",
			client.Program(),
		),
	}, createReportHandler(client))
}

func createReportHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, CreateReportInput) (*mcp.CallToolResult, CreateReportOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input CreateReportInput,
	) (*mcp.CallToolResult, CreateReportOutput, error) {
		if input.Title == "" {
			return nil, CreateReportOutput{},
				fmt.Errorf("title is required")
		}
		if input.VulnInfo == "" {
			return nil, CreateReportOutput{},
				fmt.Errorf("vulnerability_information is required")
		}
		if !validRatings[input.Severity] {
			return nil, CreateReportOutput{},
				fmt.Errorf("invalid severity_rating %q", input.Severity)
		}

		reportID, err := client.CreateReport(
			ctx, hackerone.CreateReportParams{
				Program:    input.Program,
				Title:      input.Title,
				VulnInfo:   input.VulnInfo,
				Severity:   input.Severity,
				WeaknessID: input.WeaknessID,
				ScopeID:    input.ScopeID,
			},
		)
		if err != nil {
			return nil, CreateReportOutput{},
				fmt.Errorf("create report: %w", err)
		}

		msg := fmt.Sprintf(
			"Report %s created: %s", reportID, input.Title,
		)
		output := CreateReportOutput{
			Success:  true,
			ReportID: reportID,
			Message:  msg,
		}
		return textResult(msg), output, nil
	}
}
