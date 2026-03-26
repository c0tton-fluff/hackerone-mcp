# hackerone-mcp

MCP server for HackerOne **triage teams** managing a program. Full read/write access to reports, triage workflows, bounties, and program management via the HackerOne API v1 over stdio transport.

Looking for the **hacker** MCP server? See [h1-hacker](https://github.com/c0tton-fluff/h1-hacker).

## Install

```bash
go install github.com/c0tton-fluff/hackerone-mcp/cmd/h1-client@latest
```

Or build from source:

```bash
git clone https://github.com/c0tton-fluff/hackerone-mcp.git
cd hackerone-mcp
go build -o h1-client ./cmd/h1-client
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `HACKERONE_API_ID` | Yes | API username |
| `HACKERONE_API_TOKEN` | Yes | API token |
| `HACKERONE_PROGRAM` | No | Default program handle |

### Claude Code (.mcp.json)

```json
{
  "mcpServers": {
    "hackerone": {
      "command": "/path/to/h1-client",
      "args": [],
      "env": {
        "HACKERONE_API_ID": "your-api-id",
        "HACKERONE_API_TOKEN": "your-api-token",
        "HACKERONE_PROGRAM": "your-program-handle"
      }
    }
  }
}
```

### macOS Keychain

Store credentials in Keychain and use the included `launch.sh` wrapper:

```bash
security add-generic-password -s hackerone-api-id -a hackerone -w "your-api-id"
security add-generic-password -s hackerone-api-token -a hackerone -w "your-api-token"
security add-generic-password -s hackerone-program -a hackerone -w "your-program-handle"
```

```json
{
  "mcpServers": {
    "hackerone": {
      "command": "/path/to/launch.sh",
      "args": ["/path/to/h1-client"]
    }
  }
}
```

## Tools (14)

**Read**
- `h1_list_programs` - list accessible programs
- `h1_list_reports` - list/filter reports (state, severity, reporter, assignee, dates, keyword, sort)
- `h1_get_report` - full report details with timeline and attachments
- `h1_get_scope` - program scope and policy
- `h1_list_members` - program team members
- `h1_report_summary` - aggregate stats by state/severity/bounty
- `h1_download_attachment` - download report attachments to /tmp
- `h1_incremental_activities` - recent activity feed

**Triage**
- `h1_add_comment` - add internal/public comments
- `h1_update_state` - change report state (triage, resolve, close, duplicate with original_report_id)
- `h1_update_severity` - set CVSS rating
- `h1_assign_report` - assign to team member
- `h1_add_summary` - add/update report summary
- `h1_update_title` - update report title

## Architecture

```
cmd/h1-client/main.go   # MCP server entry point (14 tools)
internal/
  hackerone/              # API client, pagination, rate limiting
  tools/                  # tool definitions and handlers
launch.sh                # macOS Keychain credential wrapper
```

## License

MIT
