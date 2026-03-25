package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validDisclosureSubstates = map[string]bool{
	"full":    true,
	"limited": true,
	"no":      true,
}

type RequestDisclosureInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Substate string `json:"substate" jsonschema:"Disclosure type: full, limited, or no"`
}

type RequestDisclosureOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterRequestDisclosureTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_request_disclosure",
		Description: "Request disclosure on a HackerOne report. " +
			"Substate: full (public), limited (redacted), or no (deny).",
	}, requestDisclosureHandler(client))
}

func requestDisclosureHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, RequestDisclosureInput) (*mcp.CallToolResult, RequestDisclosureOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input RequestDisclosureInput,
	) (*mcp.CallToolResult, RequestDisclosureOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, RequestDisclosureOutput{}, err
		}
		if !validDisclosureSubstates[input.Substate] {
			return nil, RequestDisclosureOutput{},
				fmt.Errorf(
					"invalid substate %q: must be full, limited, or no",
					input.Substate,
				)
		}

		err := client.RequestDisclosure(
			ctx, input.ReportID, input.Substate,
		)
		if err != nil {
			return nil, RequestDisclosureOutput{},
				fmt.Errorf(
					"request disclosure on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Disclosure requested on report %s (substate: %s)",
			input.ReportID, input.Substate,
		)
		output := RequestDisclosureOutput{
			Success: true, Message: msg,
		}
		return textResult(msg), output, nil
	}
}
