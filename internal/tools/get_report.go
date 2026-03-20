package tools

import (
	"context"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type GetReportInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
}

type GetReportOutput struct {
	Report     *hackerone.Report     `json:"report"`
	Activities []hackerone.Activity  `json:"activities"`
}

func RegisterGetReportTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_get_report",
		Description: "Get full details of a HackerOne report by ID. " +
			"Returns report metadata, vulnerability info, and " +
			"activity timeline (comments, state changes, bounties).",
	}, getReportHandler(client))
}

func getReportHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, GetReportInput) (*mcp.CallToolResult, GetReportOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input GetReportInput,
	) (*mcp.CallToolResult, GetReportOutput, error) {
		var activities []hackerone.Activity
		var actErr error
		done := make(chan struct{})
		go func() {
			defer close(done)
			activities, actErr = client.GetActivities(
				ctx, input.ReportID,
			)
		}()

		report, err := client.GetReport(ctx, input.ReportID)
		<-done

		if err != nil {
			return nil, GetReportOutput{}, err
		}
		if actErr != nil {
			return nil, GetReportOutput{}, actErr
		}

		output := GetReportOutput{
			Report:     report,
			Activities: activities,
		}
		result, err := jsonResult(output)
		if err != nil {
			return nil, GetReportOutput{}, err
		}
		return result, output, nil
	}
}
