package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetScopeInput struct {
	Program string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
}

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
			"Get program scope. Defaults to %s. Returns asset "+
				"types, identifiers, and eligibility.",
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
		scopes, err := client.GetProgramScope(ctx, input.Program)
		if err != nil {
			return nil, GetScopeOutput{},
				fmt.Errorf("get scope: %w", err)
		}

		output := GetScopeOutput{
			Scopes: scopes,
			Count:  len(scopes),
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, GetScopeOutput{}, err
		}
		return result, output, nil
	}
}
