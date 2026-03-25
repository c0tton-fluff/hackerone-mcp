package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdateWeaknessInput struct {
	ReportID   string `json:"report_id" jsonschema:"HackerOne report ID"`
	WeaknessID string `json:"weakness_id" jsonschema:"H1 weakness ID (numeric). Use program weaknesses list to find IDs."`
}

type UpdateWeaknessOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateWeaknessTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_update_weakness",
		Description: "Set the weakness (CWE) on a HackerOne report. " +
			"Requires the H1 weakness ID, not the CWE number.",
	}, updateWeaknessHandler(client))
}

func updateWeaknessHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateWeaknessInput) (*mcp.CallToolResult, UpdateWeaknessOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateWeaknessInput,
	) (*mcp.CallToolResult, UpdateWeaknessOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateWeaknessOutput{}, err
		}
		if input.WeaknessID == "" {
			return nil, UpdateWeaknessOutput{},
				fmt.Errorf("weakness_id is required")
		}

		err := client.UpdateWeakness(
			ctx, input.ReportID, input.WeaknessID,
		)
		if err != nil {
			return nil, UpdateWeaknessOutput{},
				fmt.Errorf(
					"update weakness on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s weakness set to %s",
			input.ReportID, input.WeaknessID,
		)
		output := UpdateWeaknessOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
