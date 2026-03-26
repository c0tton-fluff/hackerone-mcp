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
	c.mu.Lock()
	defer c.mu.Unlock()

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
	firstURL := fmt.Sprintf(
		"%s/programs/%s/structured_scopes?page[size]=100",
		c.baseURL, url.PathEscape(programID),
	)
	resources, err := c.fetchAllPages(ctx, firstURL, 0)
	if err != nil {
		return nil, err
	}

	scopes := make([]map[string]any, 0, len(resources))
	for _, r := range resources {
		if r.Attributes["archived_at"] != nil {
			continue
		}
		scope := map[string]any{"id": r.ID}
		maps.Copy(scope, r.Attributes)
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// ListMembers returns team members for a program.
func (c *Client) ListMembers(
	ctx context.Context, program string,
) ([]Member, error) {
	handle := c.resolveProgram(program)
	programID, err := c.getProgramID(ctx, handle)
	if err != nil {
		return nil, err
	}

	firstURL := fmt.Sprintf(
		"%s/programs/%s/members?page[size]=100",
		c.baseURL, url.PathEscape(programID),
	)
	resources, err := c.fetchAllPages(ctx, firstURL, 0)
	if err != nil {
		return nil, err
	}

	members := make([]Member, 0, len(resources))
	for _, r := range resources {
		m := Member{ID: r.ID}
		if userAttrs := relAttrs(r, "user"); userAttrs != nil {
			m.Username, _ = userAttrs["username"].(string)
			m.Name, _ = userAttrs["name"].(string)
		}
		members = append(members, m)
	}
	return members, nil
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

// GetAnalytics returns program analytics data.
func (c *Client) GetAnalytics(
	ctx context.Context, program, queryKey, startDate, endDate, interval string,
) (map[string]any, error) {
	handle := c.resolveProgram(program)
	params := url.Values{}
	params.Set("filter[program][]", handle)
	params.Set("filter[query_key]", queryKey)
	params.Set("filter[start_date]", startDate)
	params.Set("filter[end_date]", endDate)
	params.Set("filter[interval]", interval)

	raw, err := c.get(ctx, "/analytics?"+params.Encode())
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse analytics response: %w", err)
	}
	return result, nil
}
