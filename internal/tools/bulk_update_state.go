package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type BulkUpdateStateInput struct {
	ReportIDs []string `json:"report_ids" jsonschema:"List of HackerOne report IDs to update"`
	State     string   `json:"state" jsonschema:"New state (triaged/resolved/not-applicable/informative/duplicate/spam)"`
	Message   string   `json:"message,omitempty" jsonschema:"Message to include with each state change"`
}

type BulkUpdateResult struct {
	ReportID string `json:"report_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

type BulkUpdateStateOutput struct {
	Results   []BulkUpdateResult `json:"results"`
	Succeeded int                `json:"succeeded"`
	Failed    int                `json:"failed"`
}

func RegisterBulkUpdateStateTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_bulk_update_state",
		Description: "Change the state of multiple HackerOne reports " +
			"at once. Useful for batch-closing spam or informative " +
			"reports. Max 25 reports per call.",
	}, bulkUpdateStateHandler(client))
}

const maxBulkReports = 25

func bulkUpdateStateHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, BulkUpdateStateInput) (*mcp.CallToolResult, BulkUpdateStateOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input BulkUpdateStateInput,
	) (*mcp.CallToolResult, BulkUpdateStateOutput, error) {
		if len(input.ReportIDs) == 0 {
			return nil, BulkUpdateStateOutput{},
				fmt.Errorf("report_ids must not be empty")
		}
		if len(input.ReportIDs) > maxBulkReports {
			return nil, BulkUpdateStateOutput{},
				fmt.Errorf(
					"too many reports (%d): max %d per call",
					len(input.ReportIDs), maxBulkReports,
				)
		}
		if !hackerone.ValidStates[input.State] {
			return nil, BulkUpdateStateOutput{},
				fmt.Errorf("invalid state %q", input.State)
		}

		results := make([]BulkUpdateResult, 0, len(input.ReportIDs))
		var succeeded, failed int

		for _, id := range input.ReportIDs {
			r := BulkUpdateResult{ReportID: id}
			err := client.UpdateState(ctx, id, input.State, input.Message)
			if err != nil {
				r.Error = err.Error()
				failed++
			} else {
				r.Success = true
				succeeded++
			}
			results = append(results, r)
		}

		output := BulkUpdateStateOutput{
			Results:   results,
			Succeeded: succeeded,
			Failed:    failed,
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, BulkUpdateStateOutput{}, err
		}
		return result, output, nil
	}
}
