package hackerone

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
)

// cachedPrograms fetches and caches the program list (one API call per session).
func (c *Client) cachedPrograms(ctx context.Context) ([]Program, error) {
	if c.programCache != nil {
		return c.programCache, nil
	}

	raw, err := c.get(ctx, "/me/programs?page[size]=100")
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	programs := make([]Program, 0, len(resp.Data))
	for _, r := range resp.Data {
		p := Program{ID: r.ID}
		if h, ok := r.Attributes["handle"].(string); ok {
			p.Handle = h
		}
		programs = append(programs, p)
	}
	c.programCache = programs
	return programs, nil
}

// ListPrograms returns all programs accessible to the API token.
func (c *Client) ListPrograms(ctx context.Context) ([]Program, error) {
	return c.cachedPrograms(ctx)
}

// getProgramID resolves a program handle to its numeric ID.
func (c *Client) getProgramID(
	ctx context.Context, handle string,
) (string, error) {
	programs, err := c.cachedPrograms(ctx)
	if err != nil {
		return "", fmt.Errorf("lookup program ID: %w", err)
	}

	for _, p := range programs {
		if p.Handle == handle {
			return p.ID, nil
		}
	}
	return "", fmt.Errorf(
		"program %q not found in accessible programs", handle,
	)
}

// GetProgramScope returns structured scopes for a program.
func (c *Client) GetProgramScope(
	ctx context.Context, program string,
) ([]map[string]any, error) {
	handle := c.resolveProgram(program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf(
		"/programs/%s/structured_scopes?page[size]=100",
		url.PathEscape(programID),
	)

	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	scopes := make([]map[string]any, 0, len(resp.Data))
	for _, r := range resp.Data {
		scope := map[string]any{"id": r.ID}
		maps.Copy(scope, r.Attributes)
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// GetProgramPolicy returns the policy body for a program.
func (c *Client) GetProgramPolicy(
	ctx context.Context, program string,
) (string, error) {
	handle := c.resolveProgram(program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return "", err
	}

	raw, err := c.get(ctx, fmt.Sprintf("/programs/%s", programID))
	if err != nil {
		return "", err
	}

	var resp SingleResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("parse program response: %w", err)
	}

	policy, _ := resp.Data.Attributes["policy"].(string)
	return policy, nil
}
