package hackerone

import "testing"

func TestValidateReportID_Valid(t *testing.T) {
	for _, id := range []string{"1", "12345", "9999999"} {
		if err := ValidateReportID(id); err != nil {
			t.Errorf("ValidateReportID(%q): unexpected error: %v", id, err)
		}
	}
}

func TestValidateReportID_Invalid(t *testing.T) {
	for _, id := range []string{"", "abc", "12.5", "12 34", "-1", "0x1F"} {
		if err := ValidateReportID(id); err == nil {
			t.Errorf("ValidateReportID(%q): expected error", id)
		}
	}
}

func TestResolveProgram_Override(t *testing.T) {
	c := NewClient("id", "key", "default_prog")
	if got := c.resolveProgram("override"); got != "override" {
		t.Errorf("got %q, want override", got)
	}
}

func TestResolveProgram_Default(t *testing.T) {
	c := NewClient("id", "key", "default_prog")
	if got := c.resolveProgram(""); got != "default_prog" {
		t.Errorf("got %q, want default_prog", got)
	}
}

func TestValidStates(t *testing.T) {
	expected := []string{
		"new", "triaged", "resolved",
		"not-applicable", "informative", "duplicate", "spam",
	}
	for _, s := range expected {
		if !ValidStates[s] {
			t.Errorf("state %q should be valid", s)
		}
	}
	if ValidStates["invalid"] {
		t.Error("state 'invalid' should not be valid")
	}
}
