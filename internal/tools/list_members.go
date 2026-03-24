package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListMembersInput struct {
	Program string `json:"program,omitempty" jsonschema:"Program handle (defaults to configured program)"`
}

type ListMembersOutput struct {
	Members []hackerone.Member `json:"members"`
	Count   int               `json:"count"`
}

func RegisterListMembersTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_list_members",
		Description: fmt.Sprintf(
			"List team members for a HackerOne program. "+
				"Defaults to %s. Returns usernames needed "+
				"for h1_assign_report.",
			client.Program(),
		),
	}, listMembersHandler(client))
}

func listMembersHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, ListMembersInput) (*mcp.CallToolResult, ListMembersOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input ListMembersInput,
	) (*mcp.CallToolResult, ListMembersOutput, error) {
		members, err := client.ListMembers(ctx, input.Program)
		if err != nil {
			return nil, ListMembersOutput{},
				fmt.Errorf("list members: %w", err)
		}

		output := ListMembersOutput{
			Members: members,
			Count:   len(members),
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, ListMembersOutput{}, err
		}
		return result, output, nil
	}
}
