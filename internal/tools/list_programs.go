package tools

import (
	"context"
	"fmt"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ListProgramsInput struct {
	IncludePolicy bool `json:"include_policy"`
}

type ListProgramsOutput struct {
	Programs []hackerone.Program `json:"programs"`
	Count    int                 `json:"count"`
	Default  string              `json:"default"`
}

func RegisterListProgramsTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_list_programs",
		Description: "List all HackerOne programs accessible to " +
			"the API token. Shows handles and IDs. " +
			"Set include_policy=true to also return each " +
			"program's policy text (the page hackers see).",
	}, listProgramsHandler(client))
}

func listProgramsHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, ListProgramsInput) (*mcp.CallToolResult, ListProgramsOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input ListProgramsInput,
	) (*mcp.CallToolResult, ListProgramsOutput, error) {
		programs, err := client.ListPrograms(ctx)
		if err != nil {
			return nil, ListProgramsOutput{},
				fmt.Errorf("list programs: %w", err)
		}

		if !input.IncludePolicy {
			stripped := make([]hackerone.Program, len(programs))
			for i, p := range programs {
				stripped[i] = hackerone.Program{
					ID: p.ID, Handle: p.Handle,
				}
			}
			programs = stripped
		}

		output := ListProgramsOutput{
			Programs: programs,
			Count:    len(programs),
			Default:  client.Program(),
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, ListProgramsOutput{}, err
		}
		return result, output, nil
	}
}
