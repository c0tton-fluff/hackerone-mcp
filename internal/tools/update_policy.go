package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type UpdatePolicyInput struct {
	Program string `json:"program"`
	Policy  string `json:"policy"`
}

func RegisterUpdatePolicyTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_update_policy",
		Description: "Update the policy page of a HackerOne program " +
			"(the page hackers see with rules, scope, and " +
			"disclosure guidelines). This replaces the entire " +
			"policy -- use h1_list_programs with include_policy=true " +
			"to read the current policy first. Requires Program " +
			"Management permission on the API token.",
	}, updatePolicyHandler(client))
}

func updatePolicyHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, UpdatePolicyInput) (*mcp.CallToolResult, string, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input UpdatePolicyInput,
	) (*mcp.CallToolResult, string, error) {
		if input.Program == "" {
			return nil, "", fmt.Errorf("program is required")
		}
		if input.Policy == "" {
			return nil, "", fmt.Errorf("policy is required")
		}

		err := client.UpdateProgramPolicy(ctx, input.Program, input.Policy)
		if err != nil {
			return nil, "", fmt.Errorf("update policy: %w", err)
		}

		msg := fmt.Sprintf(
			"Policy updated for program %q.", input.Program,
		)
		return textResult(msg), msg, nil
	}
}
