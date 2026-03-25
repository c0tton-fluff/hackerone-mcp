package tools

import (
	"context"
	"fmt"
	"time"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type IncrementalActivitiesInput struct {
	Program      string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
	UpdatedAfter string `json:"updated_after,omitempty" jsonschema:"Only activities updated after this timestamp (ISO 8601, e.g. 2026-03-24T00:00:00Z)"`
	Limit        int    `json:"limit,omitempty" jsonschema:"Max activities to return (default 25, max 1000)"`
}

type IncrementalActivitiesOutput struct {
	Activities []hackerone.Activity `json:"activities"`
	Count      int                  `json:"count"`
}

func RegisterIncrementalActivitiesTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_incremental_activities",
		Description: fmt.Sprintf(
			"Poll for new activities across all reports. "+
				"Defaults to program %s. Use updated_after "+
				"to get only recent activity.",
			client.Program(),
		),
	}, incrementalActivitiesHandler(client))
}

func incrementalActivitiesHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, IncrementalActivitiesInput) (*mcp.CallToolResult, IncrementalActivitiesOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input IncrementalActivitiesInput,
	) (*mcp.CallToolResult, IncrementalActivitiesOutput, error) {
		if input.UpdatedAfter != "" {
			if _, err := time.Parse(time.RFC3339, input.UpdatedAfter); err != nil {
				return nil, IncrementalActivitiesOutput{},
					fmt.Errorf(
						"invalid updated_after %q: use ISO 8601 (e.g. 2026-03-24T00:00:00Z)",
						input.UpdatedAfter,
					)
			}
		}

		activities, err := client.IncrementalActivities(
			ctx, input.Program, input.UpdatedAfter, input.Limit,
		)
		if err != nil {
			return nil, IncrementalActivitiesOutput{},
				fmt.Errorf("incremental activities: %w", err)
		}

		output := IncrementalActivitiesOutput{
			Activities: activities,
			Count:      len(activities),
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, IncrementalActivitiesOutput{}, err
		}
		return result, output, nil
	}
}
