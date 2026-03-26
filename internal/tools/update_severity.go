package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validRatings = map[string]bool{
	"none": true, "low": true, "medium": true, "high": true, "critical": true,
}

type UpdateSeverityInput struct {
	ReportID   string `json:"report_id" jsonschema:"HackerOne report ID"`
	Rating     string `json:"rating,omitempty" jsonschema:"Severity rating (none/low/medium/high/critical). Required unless cvss_vector is provided."`
	CvssVector string `json:"cvss_vector,omitempty" jsonschema:"CVSS 3.x vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Expanded into individual API fields."`
}

type UpdateSeverityOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateSeverityTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_update_severity",
		Description: "Update the severity rating and optional CVSS " +
			"vector on a HackerOne report.",
	}, updateSeverityHandler(client))
}

func updateSeverityHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateSeverityInput) (*mcp.CallToolResult, UpdateSeverityOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateSeverityInput,
	) (*mcp.CallToolResult, UpdateSeverityOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateSeverityOutput{}, err
		}
		if input.Rating == "" && input.CvssVector == "" {
			return nil, UpdateSeverityOutput{},
				fmt.Errorf("rating or cvss_vector required")
		}
		if input.Rating != "" && !validRatings[input.Rating] {
			return nil, UpdateSeverityOutput{},
				fmt.Errorf("invalid rating %q", input.Rating)
		}

		err := client.UpdateSeverity(
			ctx, input.ReportID, input.Rating, input.CvssVector,
		)
		if err != nil {
			return nil, UpdateSeverityOutput{},
				fmt.Errorf(
					"update severity on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s severity set to %s",
			input.ReportID, input.Rating,
		)
		if input.CvssVector != "" {
			msg += fmt.Sprintf(" (%s)", input.CvssVector)
		}
		output := UpdateSeverityOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
