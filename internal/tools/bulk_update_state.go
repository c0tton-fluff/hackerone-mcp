package tools

import (
	"context"
	"fmt"
	"sync"

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

const (
	maxBulkReports = 25
	bulkWorkers    = 5
)

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
		if !hackerone.ValidTransitionStates[input.State] {
			return nil, BulkUpdateStateOutput{},
				fmt.Errorf("invalid state %q", input.State)
		}

		results := make([]BulkUpdateResult, len(input.ReportIDs))
		var wg sync.WaitGroup
		sem := make(chan struct{}, bulkWorkers)

		for i, id := range input.ReportIDs {
			results[i].ReportID = id
			if ctxErr := ctx.Err(); ctxErr != nil {
				results[i].Error = ctxErr.Error()
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, reportID string) {
				defer wg.Done()
				defer func() { <-sem }()
				err := client.UpdateState(
					ctx, reportID, input.State, input.Message,
				)
				if err != nil {
					results[idx].Error = err.Error()
				} else {
					results[idx].Success = true
				}
			}(i, id)
		}
		wg.Wait()

		var succeeded, failed int
		for _, r := range results {
			if r.Success {
				succeeded++
			} else if r.Error != "" {
				failed++
			}
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
