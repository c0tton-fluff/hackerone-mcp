package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/c0tton-fluff/hackerone-mcp/internal/hackerone"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxDownloadSize = 250 * 1024 * 1024 // 250 MB - matches H1 upload limit

type DownloadAttachmentInput struct {
	ReportID string `json:"report_id" jsonschema:"HackerOne report ID"`
	Filename string `json:"filename,omitempty" jsonschema:"Specific attachment filename. Optional if report has only one attachment."`
}

type DownloadAttachmentOutput struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	FilePath string `json:"file_path,omitempty"`
}

func RegisterDownloadAttachmentTool(
	server *mcp.Server, client *hackerone.Client,
) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "h1_download_attachment",
		Description: "Download a report attachment to /tmp. " +
			"Auto-selects if only one attachment. " +
			"For images, use the Read tool on the returned path to view. " +
			"For videos, use open via Bash to play.",
	}, downloadAttachmentHandler(client))
}

func downloadAttachmentHandler(
	client *hackerone.Client,
) func(context.Context, *mcp.CallToolRequest, DownloadAttachmentInput) (*mcp.CallToolResult, DownloadAttachmentOutput, error) {
	return func(
		ctx context.Context,
		req *mcp.CallToolRequest,
		input DownloadAttachmentInput,
	) (*mcp.CallToolResult, DownloadAttachmentOutput, error) {
		if err := hackerone.ValidateReportID(input.ReportID); err != nil {
			return nil, DownloadAttachmentOutput{}, err
		}

		atts, err := client.GetReportAttachments(ctx, input.ReportID)
		if err != nil {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("fetch attachments for report %s: %w", input.ReportID, err)
		}

		if len(atts) == 0 {
			msg := fmt.Sprintf("No attachments on report #%s.", input.ReportID)
			return textResult(msg),
				DownloadAttachmentOutput{Message: msg}, nil
		}

		var target hackerone.Attachment
		if input.Filename == "" {
			if len(atts) == 1 {
				target = atts[0]
			} else {
				msg := fmt.Sprintf(
					"Report #%s has %d attachments - specify a filename:\n",
					input.ReportID, len(atts),
				)
				for i, a := range atts {
					msg += fmt.Sprintf(
						"%d. %s (%s, %s)\n",
						i+1, a.FileName, a.ContentType,
						formatFileSize(a.FileSize),
					)
				}
				return textResult(msg),
					DownloadAttachmentOutput{Message: msg}, nil
			}
		} else {
			found := false
			for _, a := range atts {
				if a.FileName == input.Filename {
					target = a
					found = true
					break
				}
			}
			if !found {
				msg := fmt.Sprintf(
					"No attachment named %q on report #%s. Available:\n",
					input.Filename, input.ReportID,
				)
				for i, a := range atts {
					msg += fmt.Sprintf(
						"%d. %s (%s, %s)\n",
						i+1, a.FileName, a.ContentType,
						formatFileSize(a.FileSize),
					)
				}
				return textResult(msg),
					DownloadAttachmentOutput{Message: msg}, nil
			}
		}

		if target.ExpiringURL == "" {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("attachment has no download URL")
		}

		u, err := url.Parse(target.ExpiringURL)
		if err != nil {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("invalid attachment URL: %w", err)
		}
		host := strings.ToLower(u.Hostname())
		if !strings.Contains(host, "s3") || !strings.HasSuffix(host, ".amazonaws.com") {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("unexpected attachment host: %s", host)
		}

		if target.FileSize > maxDownloadSize {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf(
					"attachment too large (%s, max 250 MB)",
					formatFileSize(target.FileSize),
				)
		}

		dlClient := &http.Client{Timeout: 5 * time.Minute}
		resp, err := dlClient.Get(target.ExpiringURL)
		if err != nil {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("downloading attachment: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}

		if resp.ContentLength > maxDownloadSize {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf(
					"attachment too large (%s, max 250 MB)",
					formatFileSize(float64(resp.ContentLength)),
				)
		}

		safeName := filepath.Base(target.FileName)
		if safeName == "." || safeName == "/" {
			safeName = fmt.Sprintf("attachment-%s", target.ID)
		}
		destPath := filepath.Join("/tmp", safeName)

		f, err := os.Create(destPath)
		if err != nil {
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("creating file: %w", err)
		}
		defer f.Close()

		written, err := io.Copy(f, io.LimitReader(resp.Body, maxDownloadSize+1))
		if err != nil {
			os.Remove(destPath)
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("writing file: %w", err)
		}
		if written > maxDownloadSize {
			os.Remove(destPath)
			return nil, DownloadAttachmentOutput{},
				fmt.Errorf("attachment exceeded 250 MB during download")
		}

		msg := fmt.Sprintf(
			"Downloaded %s (%s) to %s",
			safeName, formatFileSize(float64(written)), destPath,
		)
		output := DownloadAttachmentOutput{
			Success:  true,
			Message:  msg,
			FilePath: destPath,
		}
		return textResult(msg), output, nil
	}
}

func formatFileSize(bytes float64) string {
	switch {
	case bytes < 1024:
		return fmt.Sprintf("%.0f B", bytes)
	case bytes < 1024*1024:
		return fmt.Sprintf("%.1f KB", bytes/1024)
	case bytes < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", bytes/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", bytes/(1024*1024*1024))
	}
}
