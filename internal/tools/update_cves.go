package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var validCVEPattern = regexp.MustCompile(
	`^CVE-\d{4}-\d{4,}$`,
)

type UpdateCVEsInput struct {
	ReportID string   `json:"report_id" jsonschema:"HackerOne report ID"`
	CVEIDs   []string `json:"cve_ids" jsonschema:"List of CVE IDs (e.g. CVE-2026-12345)"`
}

type UpdateCVEsOutput struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func RegisterUpdateCVEsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_update_cves",
		Description: "Set CVE IDs on a HackerOne report. " +
			"Replaces all existing CVE associations.",
	}, updateCVEsHandler(client))
}

func updateCVEsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdateCVEsInput) (*mcp.CallToolResult, UpdateCVEsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdateCVEsInput,
	) (*mcp.CallToolResult, UpdateCVEsOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, UpdateCVEsOutput{}, err
		}
		if len(input.CVEIDs) == 0 {
			return nil, UpdateCVEsOutput{},
				fmt.Errorf("cve_ids is required (non-empty list)")
		}
		for _, id := range input.CVEIDs {
			if !validCVEPattern.MatchString(id) {
				return nil, UpdateCVEsOutput{},
					fmt.Errorf(
						"invalid CVE ID %q: expected format CVE-YYYY-NNNNN",
						id,
					)
			}
		}

		err := client.UpdateCVEs(
			ctx, input.ReportID, input.CVEIDs,
		)
		if err != nil {
			return nil, UpdateCVEsOutput{},
				fmt.Errorf(
					"update CVEs on %s: %w",
					input.ReportID, err,
				)
		}

		msg := fmt.Sprintf(
			"Report %s CVEs set to [%s]",
			input.ReportID, strings.Join(input.CVEIDs, ", "),
		)
		output := UpdateCVEsOutput{Success: true, Message: msg}
		return textResult(msg), output, nil
	}
}
