package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ReportSummaryInput struct {
	Program string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
}

type ReportSummaryOutput struct {
	TotalReports int                `json:"total_reports"`
	ByState      map[string]int     `json:"by_state"`
	BySeverity   map[string]int     `json:"by_severity"`
	Bounty       *BountySummary     `json:"bounty,omitempty"`
}

type BountySummary struct {
	Total   float64 `json:"total"`
	Bonus   float64 `json:"bonus,omitzero"`
	Count   int     `json:"count"`
	Average float64 `json:"average"`
}

func RegisterReportSummaryTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_report_summary",
		Description: fmt.Sprintf(
			"Aggregate program stats for %s: report counts "+
				"by state and severity, bounty totals and averages. "+
				"Fetches all reports so may take a moment for large programs.",
			client.Program(),
		),
	}, reportSummaryHandler(client))
}

func reportSummaryHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, ReportSummaryInput) (*mcp.CallToolResult, ReportSummaryOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input ReportSummaryInput,
	) (*mcp.CallToolResult, ReportSummaryOutput, error) {
		reports, err := client.ListReports(ctx, hackerone.ReportFilter{
			Program: input.Program,
			Limit:   0,
		})
		if err != nil {
			return nil, ReportSummaryOutput{},
				fmt.Errorf("fetch reports for summary: %w", err)
		}

		byState := map[string]int{}
		bySev := map[string]int{}
		var bountyTotal, bonusTotal float64
		var bountyCount int

		for _, r := range reports {
			byState[r.State]++
			sev := r.Severity
			if sev == "" {
				sev = "none"
			}
			bySev[sev]++
			if r.BountyAmount > 0 || r.BountyBonusAmount > 0 {
				bountyTotal += r.BountyAmount
				bonusTotal += r.BountyBonusAmount
				bountyCount++
			}
		}

		output := ReportSummaryOutput{
			TotalReports: len(reports),
			ByState:      byState,
			BySeverity:   bySev,
		}
		if bountyCount > 0 {
			output.Bounty = &BountySummary{
				Total:   bountyTotal,
				Bonus:   bonusTotal,
				Count:   bountyCount,
				Average: bountyTotal / float64(bountyCount),
			}
		}

		result, err := jsonResult(output)
		if err != nil {
			return nil, ReportSummaryOutput{}, err
		}
		return result, output, nil
	}
}
