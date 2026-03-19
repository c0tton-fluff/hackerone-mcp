package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type AwardBountyInput struct {
	ReportID string  `json:"report_id" jsonschema:"HackerOne report ID"`
	Amount   float64 `json:"amount" jsonschema:"Bounty amount in USD"`
	Message  string  `json:"message,omitempty" jsonschema:"Message to researcher with the bounty award"`
}

type AwardBountyOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterAwardBountyTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "h1_award_bounty",
		Description: "Award a bounty on a HackerOne report. Specify amount in USD.",
	}, awardBountyHandler(client))
}

func awardBountyHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, AwardBountyInput) (*mcp.CallToolResult, AwardBountyOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input AwardBountyInput,
	) (*mcp.CallToolResult, AwardBountyOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, AwardBountyOutput{}, err
		}
		if input.Amount <= 0 {
			return nil, AwardBountyOutput{},
				fmt.Errorf("amount must be positive")
		}

		err := client.AwardBounty(
			ctx, input.ReportID, input.Amount, input.Message,
		)
		if err != nil {
			return nil, AwardBountyOutput{},
				fmt.Errorf(
					"award bounty on %s: %w",
					input.ReportID, err,
				)
		}

		output := AwardBountyOutput{
			Success: true,
			Message: fmt.Sprintf(
				"Awarded $%.2f bounty on report %s",
				input.Amount, input.ReportID,
			),
		}
		return textResult(output.Message), output, nil
	}
}
