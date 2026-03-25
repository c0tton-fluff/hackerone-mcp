package cmd

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/c0tton-fluff/hackerone-mcp/internal/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server (stdio transport)",
	RunE: func(cmd *cobra.Command, args []string) error {
		apiID := os.Getenv("HACKERONE_API_ID")
		apiKey := os.Getenv("HACKERONE_API_TOKEN")
		program := os.Getenv("HACKERONE_PROGRAM")

		if apiID == "" || apiKey == "" {
			return fmt.Errorf(
				"HACKERONE_API_ID and HACKERONE_API_TOKEN env vars required",
			)
		}
		if program == "" {
			return fmt.Errorf(
				"HACKERONE_PROGRAM env var required (your program handle)",
			)
		}

		client := hackerone.NewClient(apiID, apiKey, program)

		server := mcp.NewServer(
			&mcp.Implementation{
				Name:    "hackerone-mcp",
				Version: "1.0.0",
			},
			nil,
		)

		tools.RegisterListProgramsTool(server, client)
		tools.RegisterListReportsTool(server, client)
		tools.RegisterGetReportTool(server, client)
		tools.RegisterAddCommentTool(server, client)
		tools.RegisterUpdateStateTool(server, client)
		tools.RegisterBulkUpdateStateTool(server, client)
		tools.RegisterMarkDuplicateTool(server, client)
		tools.RegisterAwardBountyTool(server, client)
		tools.RegisterUpdateSeverityTool(server, client)
		tools.RegisterAssignReportTool(server, client)
		tools.RegisterListMembersTool(server, client)
		tools.RegisterGetScopeTool(server, client)
		tools.RegisterUpdateTitleTool(server, client)
		tools.RegisterUpdateWeaknessTool(server, client)
		tools.RegisterUpdateTagsTool(server, client)
		tools.RegisterRequestDisclosureTool(server, client)
		tools.RegisterIncrementalActivitiesTool(server, client)
		tools.RegisterAddSummaryTool(server, client)
		tools.RegisterUpdateCVEsTool(server, client)
		tools.RegisterCloseCommentsTool(server, client)
		tools.RegisterManageRetestTool(server, client)
		tools.RegisterGetAnalyticsTool(server, client)
		tools.RegisterCreateReportTool(server, client)
		tools.RegisterReportSummaryTool(server, client)
		tools.RegisterDownloadAttachmentTool(server, client)

		// Parent PID watchdog -- exit if parent dies.
		parentPid := os.Getppid()
		go func() {
			for {
				time.Sleep(2 * time.Second)
				if err := syscall.Kill(parentPid, 0); err != nil {
					os.Exit(0)
				}
			}
		}()

		return server.Run(
			context.Background(), &mcp.StdioTransport{},
		)
	},
}
