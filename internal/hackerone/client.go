package hackerone

import (
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"
)

var validReportID = regexp.MustCompile(`^\d+$`)

const (
	defaultBaseURL = "https://api.hackerone.com/v1"
	maxRetries     = 3
	maxReports     = 1000
)

// ValidStates contains valid report states for filtering.
var ValidStates = map[string]bool{
	"new":                    true,
	"triaged":                true,
	"needs-more-info":        true,
	"resolved":               true,
	"not-applicable":         true,
	"informative":            true,
	"duplicate":              true,
	"spam":                   true,
	"pending-program-review": true,
}

// ValidTransitionStates contains states valid for state_change API calls.
// "new" is excluded -- it is the initial state and cannot be transitioned to.
var ValidTransitionStates = map[string]bool{
	"triaged":                true,
	"needs-more-info":        true,
	"resolved":               true,
	"not-applicable":         true,
	"informative":            true,
	"duplicate":              true,
	"spam":                   true,
	"pending-program-review": true,
}

// MessageRequiredStates are states that require a message in the state change.
var MessageRequiredStates = map[string]bool{
	"needs-more-info": true,
	"informative":     true,
	"duplicate":       true,
}

type Client struct {
	http         *http.Client
	apiID        string
	apiKey       string
	program      string
	baseURL      string
	mu           sync.Mutex
	programCache []Program
}

func NewClient(apiID, apiKey, program string) *Client {
	return &Client{
		http:    &http.Client{Timeout: 30 * time.Second},
		apiID:   apiID,
		apiKey:  apiKey,
		program: program,
		baseURL: defaultBaseURL,
	}
}

func (c *Client) Program() string { return c.program }

func ValidateReportID(id string) error {
	if !validReportID.MatchString(id) {
		return fmt.Errorf(
			"invalid report ID %q: must be numeric", id,
		)
	}
	return nil
}

func (c *Client) reportPath(reportID string) string {
	return fmt.Sprintf("/reports/%s", reportID)
}

func (c *Client) resolveProgram(handle string) string {
	if handle != "" {
		return handle
	}
	return c.program
}
