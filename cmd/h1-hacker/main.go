package main

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

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

	client := hackerone.NewHackerClient(apiID, apiKey, program)

	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "h1-hacker",
			Version: "1.1.0",
		},
		nil,
	)

	tools.RegisterListProgramsTool(server, client)
	tools.RegisterListReportsTool(server, client)
	tools.RegisterGetReportTool(server, client)
	tools.RegisterGetScopeTool(server, client)
	tools.RegisterCreateReportTool(server, client)
	tools.RegisterReportSummaryTool(server, client)
	tools.RegisterDownloadAttachmentTool(server, client)

	// Parent PID watchdog -- exit if parent dies.
	ppid := os.Getppid()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if err := syscall.Kill(ppid, 0); err != nil {
				os.Exit(0)
			}
		}
	}()

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
