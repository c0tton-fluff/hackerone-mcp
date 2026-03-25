# hackerone-mcp

Two MCP servers for HackerOne - one for **triage teams** managing a program, one for **hackers** hunting bugs. Both use the HackerOne API v1 over stdio transport.

## Install

```bash
# Triage / VDP management (25 tools)
go install github.com/c0tton-fluff/hackerone-mcp/cmd/h1-client@latest

# Bug bounty hunting (7 tools)
go install github.com/c0tton-fluff/hackerone-mcp/cmd/h1-hacker@latest
```

Or build from source:

```bash
git clone https://github.com/c0tton-fluff/hackerone-mcp.git
cd hackerone-mcp
go build -o h1-client ./cmd/h1-client
go build -o h1-hacker ./cmd/h1-hacker
```

## Configuration

Both servers need HackerOne API credentials as environment variables:

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
security add-generic-password -s hackerone-api-id -a hackerone -w "your-api-id" (this is simply your username)
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

---

## H1-Client (Triage / VDP)

For security teams managing a HackerOne program. Full read/write access to reports, triage workflows, bounties, and program management.

### Tools (25)

**Read**
- `h1_list_programs` - list accessible programs
- `h1_list_reports` - list/filter reports (state, severity, dates, keyword, batch IDs)
- `h1_get_report` - full report details with timeline and attachments
- `h1_get_scope` - program scope and policy
- `h1_list_members` - program team members
- `h1_report_summary` - aggregate stats by state/severity/bounty
- `h1_download_attachment` - download report attachments to /tmp
- `h1_get_analytics` - program analytics (response times, stats)
- `h1_incremental_activities` - recent activity feed

**Triage**
- `h1_add_comment` - add internal/public comments
- `h1_update_state` - change report state (triage, resolve, close)
- `h1_bulk_update_state` - batch state changes
- `h1_mark_duplicate` - mark as duplicate with original ID
- `h1_award_bounty` - award bounty and bonus
- `h1_update_severity` - set CVSS rating
- `h1_assign_report` - assign to team member
- `h1_add_summary` - add/update report summary
- `h1_update_cves` - set CVE IDs
- `h1_close_comments` - lock report comments
- `h1_manage_retest` - request/manage retests
- `h1_update_title` - update report title
- `h1_update_tags` - add/remove tags
- `h1_update_weakness` - set weakness/CWE
- `h1_request_disclosure` - request public disclosure
- `h1_create_report` - submit a report

---

## H1-Hacker (Bug Bounty)

For bug bounty hunters. Read-only access to programs, scopes, and reports, plus report submission. No triage or program management tools.

### Tools (7)

- `h1_list_programs` - list accessible programs
- `h1_list_reports` - list/filter your reports
- `h1_get_report` - full report details
- `h1_get_scope` - program scope and policy
- `h1_create_report` - submit a new report
- `h1_report_summary` - your bounty stats
- `h1_download_attachment` - download report attachments

---

## Architecture

```
cmd/
  h1-client/main.go     # triage server (25 tools)
  h1-hacker/main.go     # hacker server (7 tools)
internal/
  hackerone/             # shared API client, pagination, rate limiting
  tools/                 # shared tool definitions (each server picks its subset)
launch.sh                # macOS Keychain credential wrapper
```

Both binaries share `internal/hackerone/` (HTTP client, auth, pagination, rate limiting) and `internal/tools/` (tool handlers). Each binary registers only the tools it needs.

## License

MIT
