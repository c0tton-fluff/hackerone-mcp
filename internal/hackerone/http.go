package hackerone

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, c.baseURL+path, nil)
}

func (c *Client) getURL(ctx context.Context, fullURL string) ([]byte, error) {
	return c.do(ctx, http.MethodGet, fullURL, nil)
}

func (c *Client) post(ctx context.Context, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal body: %w", err)
	}
	return c.do(ctx, http.MethodPost, c.baseURL+path, payload)
}

// do executes an HTTP request with automatic retry on 429 rate limits.
func (c *Client) do(
	ctx context.Context, method, reqURL string, body []byte,
) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		data, retryAfter, err := c.doOnce(ctx, method, reqURL, body)
		if err == nil {
			return data, nil
		}
		if retryAfter == 0 || attempt >= maxRetries {
			return nil, err
		}
		backoff := max(retryAfter, time.Duration(1<<uint(attempt))*time.Second)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// doOnce executes a single HTTP request. Returns retryAfter > 0 on 429.
func (c *Client) doOnce(
	ctx context.Context, method, reqURL string, body []byte,
) ([]byte, time.Duration, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}

	req.SetBasicAuth(c.apiID, c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("request %s %s: %w", method, reqURL, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, 0, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := parseRetryAfter(resp.Header)
		return nil, wait, fmt.Errorf("rate limited (429)")
	}

	if resp.StatusCode >= 400 {
		snippet := string(data)
		if len(snippet) > 200 {
			snippet = snippet[:200] + "..."
		}
		return nil, 0, fmt.Errorf(
			"%s %s returned %d: %s",
			method, reqURL, resp.StatusCode, snippet,
		)
	}

	return data, 0, nil
}

// fetchAllPages fetches all pages of a paginated JSON:API endpoint.
// If limit > 0, stops after collecting that many resources.
func (c *Client) fetchAllPages(
	ctx context.Context, firstURL string, limit int,
) ([]Resource, error) {
	var all []Resource
	nextURL := firstURL
	for nextURL != "" {
		if limit > 0 && len(all) >= limit {
			break
		}
		if !strings.HasPrefix(nextURL, c.baseURL) {
			return nil, fmt.Errorf(
				"pagination URL not under API base: %s", nextURL,
			)
		}
		raw, err := c.getURL(ctx, nextURL)
		if err != nil {
			return nil, err
		}
		var resp ListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("parse response: %w", err)
		}
		all = append(all, resp.Data...)
		nextURL = resp.Links.Next
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func parseRetryAfter(h http.Header) time.Duration {
	val := h.Get("Retry-After")
	if val == "" {
		return 2 * time.Second
	}
	var wait time.Duration
	if secs, err := strconv.Atoi(val); err == nil {
		wait = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(val); err == nil {
		wait = time.Until(t)
	}
	if wait <= 0 {
		wait = 2 * time.Second
	}
	if wait > 60*time.Second {
		wait = 60 * time.Second
	}
	return wait
}
