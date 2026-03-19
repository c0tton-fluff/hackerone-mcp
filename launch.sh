#!/bin/bash
# Launch script for hackerone-mcp.
# Set HACKERONE_API_ID, HACKERONE_API_TOKEN, and HACKERONE_PROGRAM
# as environment variables before running, or source them from your
# preferred secret store (e.g. macOS Keychain, 1Password CLI, Vault).
#
# Example with macOS Keychain:
#   export HACKERONE_API_ID=$(security find-generic-password -s hackerone-api-id -w)
#   export HACKERONE_API_TOKEN=$(security find-generic-password -s hackerone-api-token -w)
#   export HACKERONE_PROGRAM=your-program-handle

if [ -z "$HACKERONE_API_ID" ] || [ -z "$HACKERONE_API_TOKEN" ] || [ -z "$HACKERONE_PROGRAM" ]; then
    echo "Error: HACKERONE_API_ID, HACKERONE_API_TOKEN, and HACKERONE_PROGRAM must be set" >&2
    exit 1
fi

exec "$(dirname "$0")/hackerone-mcp" serve
