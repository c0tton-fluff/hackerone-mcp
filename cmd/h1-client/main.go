package main

import (
	"context"
	"fmt"
	"os"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/c0tton-fluff/hackerone-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	apiID := os.Getenv("HACKERONE_API_ID")
	apiKey := os.Getenv("HACKERONE_API_TOKEN")
	program := os.Getenv("HACKERONE_PROGRAM")

	if apiID == "" || apiKey == "" {
		fmt.Fprintln(os.Stderr,
			"HACKERONE_API_ID and HACKERONE_API_TOKEN env vars required")
		os.Exit(1)
	}

	client := hackerone.NewClient(apiID, apiKey, program)

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "h1-client",
			Version: "1.1.0",
		},
		nil,
	)

	// Read tools
	tools.RegisterListProgramsTool(server, client)
	tools.RegisterListReportsTool(server, client)
	tools.RegisterGetReportTool(server, client)
	tools.RegisterGetScopeTool(server, client)
	tools.RegisterListMembersTool(server, client)
	tools.RegisterReportSummaryTool(server, client)
	tools.RegisterDownloadAttachmentTool(server, client)
	tools.RegisterGetAnalyticsTool(server, client)
	tools.RegisterIncrementalActivitiesTool(server, client)

	// Triage tools
	tools.RegisterAddCommentTool(server, client)
	tools.RegisterUpdateStateTool(server, client)
	tools.RegisterBulkUpdateStateTool(server, client)
	tools.RegisterMarkDuplicateTool(server, client)
	tools.RegisterAwardBountyTool(server, client)
	tools.RegisterUpdateSeverityTool(server, client)
	tools.RegisterAssignReportTool(server, client)
	tools.RegisterAddSummaryTool(server, client)
	tools.RegisterUpdateCVEsTool(server, client)
	tools.RegisterCloseCommentsTool(server, client)
	tools.RegisterManageRetestTool(server, client)
	tools.RegisterUpdateTitleTool(server, client)
	tools.RegisterUpdateTagsTool(server, client)
	tools.RegisterUpdateWeaknessTool(server, client)
	tools.RegisterRequestDisclosureTool(server, client)
	tools.RegisterCreateReportTool(server, client)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
