package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetScopeInput struct{}

type GetScopeOutput struct {
	Scopes []map[string]any `json:"scopes"`
	Count  int              `json:"count"`
}

func RegisterGetScopeTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_get_scope",
		Description: fmt.Sprintf(
			"Get program scope for %s. Returns asset types, identifiers, and eligibility.",
			client.Program(),
		),
	}, getScopeHandler(client))
}

func getScopeHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, GetScopeInput) (*mcp.CallToolResult, GetScopeOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input GetScopeInput,
	) (*mcp.CallToolResult, GetScopeOutput, error) {
		scopes, err := client.GetProgramScope(ctx)
		if err != nil {
			return nil, GetScopeOutput{},
				fmt.Errorf("get scope: %w", err)
		}

		output := GetScopeOutput{
			Scopes: scopes,
			Count:  len(scopes),
		}
		text, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return nil, GetScopeOutput{}, fmt.Errorf("marshal output: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(text)},
			},
		}, output, nil
	}
}
