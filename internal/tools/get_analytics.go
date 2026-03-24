package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetAnalyticsInput struct {
	Program string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
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
		data, err := client.GetAnalytics(ctx, input.Program)
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
