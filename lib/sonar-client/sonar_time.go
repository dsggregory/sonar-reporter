package sonar_client

import (
	"fmt"
	"strings"
	"time"
)

// CustomTime is a wrapper around time.Time that implements custom JSON unmarshaling
type CustomTime struct {
	time.Time
}

// UnmarshalJSON implements the json.Unmarshaler interface for CustomTime
func (ct *CustomTime) UnmarshalJSON(b []byte) error {
	// Remove quotes from string
	s := strings.Trim(string(b), `"`)

	// Handle empty string or null
	if s == "" || s == "null" {
		ct.Time = time.Time{}
		return nil
	}

	// Try parsing with different RFC3339 variations
	formats := []string{
		"2006-01-02T15:04:05Z0700", // RFC3339 without colon (:) in TZ offset
		time.RFC3339,               // "2006-01-02T15:04:05Z07:00"
		time.RFC3339Nano,           // "2006-01-02T15:04:05.999999999Z07:00"
		"2006-01-02T15:04:05Z",     // Without timezone
		"2006-01-02T15:04:05",      // Without Z and timezone
	}

	var err error
	var t time.Time
	for _, format := range formats {
		t, err = time.Parse(format, s)
		if err == nil {
			ct.Time = t
			return nil
		}
	}

	return fmt.Errorf("failed to parse time %q: %v", s, err)
}

// MarshalJSON implements the json.Marshaler interface for CustomTime
func (ct CustomTime) MarshalJSON() ([]byte, error) {
	if ct.Time.IsZero() {
		return []byte(`null`), nil
	}
	return []byte(fmt.Sprintf(`"%s"`, ct.Time.Format(time.RFC3339))), nil
}
