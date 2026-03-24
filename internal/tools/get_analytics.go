package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetAnalyticsInput struct {
	Program   string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	QueryKey  string `json:"query_key" jsonschema:"Analytics metric (e.g. reports_by_severity, reports_by_state, reports_by_asset, reports_by_weakness, bounties_by_severity)"`
	StartDate string `json:"start_date" jsonschema:"Start date (YYYY-MM-DD)"`
	EndDate   string `json:"end_date" jsonschema:"End date (YYYY-MM-DD)"`
	Interval  string `json:"interval" jsonschema:"Aggregation interval (day, week, month)"`
}

type GetAnalyticsOutput struct {
	Analytics map[string]any `json:"analytics"`
}

func RegisterGetAnalyticsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_get_analytics",
		Description: fmt.Sprintf(
			"Get program analytics for a HackerOne program. "+
				"Requires query_key, start_date, end_date, interval. "+
				"Defaults to %s.",
			client.Program(),
		),
	}, getAnalyticsHandler(client))
}

func getAnalyticsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, GetAnalyticsInput) (*mcp.CallToolResult, GetAnalyticsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input GetAnalyticsInput,
	) (*mcp.CallToolResult, GetAnalyticsOutput, error) {
		if input.QueryKey == "" {
			return nil, GetAnalyticsOutput{},
				fmt.Errorf("query_key is required")
		}
		if input.StartDate == "" || input.EndDate == "" {
			return nil, GetAnalyticsOutput{},
				fmt.Errorf("start_date and end_date are required")
		}
		if input.Interval == "" {
			return nil, GetAnalyticsOutput{},
				fmt.Errorf("interval is required (day, week, or month)")
		}

		data, err := client.GetAnalytics(
			ctx, input.Program,
			input.QueryKey, input.StartDate, input.EndDate, input.Interval,
		)
		if err != nil {
			return nil, GetAnalyticsOutput{},
				fmt.Errorf("get analytics: %w", err)
		}

		output := GetAnalyticsOutput{Analytics: data}
		result, err := jsonResult(output)
		if err != nil {
			return nil, GetAnalyticsOutput{}, err
		}
		return result, output, nil
	}
}
