package sonar_client

import (
	"encoding/json"
	"fmt"
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

type ErrorResponse struct {
	Errors []struct {
		Msg string `json:"msg"`
	} `json:"errors"`
}

// responseError handle Sonar API errors
func (c *SonarClient) responseError(resp *http.Response, msg string) error {
	var emsg ErrorResponse
	if json.NewDecoder(resp.Body).Decode(&emsg) != nil {
		return fmt.Errorf(msg)
	}

	return fmt.Errorf("%s. %s", msg, emsg.Errors[0].Msg)
}
