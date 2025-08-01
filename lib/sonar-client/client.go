package sonar_client

import (
	"net/http"
	"time"
)

// SonarClient represents a SonarQube API client
type SonarClient struct {
	baseURL string
	// token MUST be a User-type token and not something like a Project-Analysis token
	token      string
	httpClient *http.Client
}

// NewSonarClient creates a new SonarQube client
func NewSonarClient(baseURL, token string) *SonarClient {
	return &SonarClient{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
