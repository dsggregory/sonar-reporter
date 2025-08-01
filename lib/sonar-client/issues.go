// file handle search and report using https://next.sonarqube.com/sonarqube/web_api/api/issues
package sonar_client

import (
	"SonarReporter/lib/config"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
)

type IssuesSearchResponse struct {
	Total  int     `json:"total"`
	P      int     `json:"p"`
	Ps     int     `json:"ps"`
	Paging Paging  `json:"paging"`
	Issues []Issue `json:"issues"`
}

type Issue struct {
	Key          string   `json:"key"`
	Rule         string   `json:"rule"`
	Severity     string   `json:"severity"`
	Component    string   `json:"component"`
	Project      string   `json:"project"`
	Line         *int     `json:"line,omitempty"`
	Status       string   `json:"status"`
	Message      string   `json:"message"`
	Effort       string   `json:"effort,omitempty"`
	Debt         string   `json:"debt,omitempty"`
	Author       string   `json:"author,omitempty"`
	Tags         []string `json:"tags"`
	CreationDate string   `json:"creationDate"`
	UpdateDate   string   `json:"updateDate"`
	Type         string   `json:"type"`
}

var typePriority = map[string]int{
	"VULNERABILITY": 0,
	"BUG":           1,
	"CODE_SMELL":    2,
}

var severityPriority = map[string]int{
	"BLOCKER":  0,
	"CRITICAL": 1,
	"MAJOR":    2,
	"MINOR":    3,
	"INFO":     4,
	"TRIVIAL":  5,
}

func sortIssues(issues []Issue) {
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Type != issues[j].Type {
			return typePriority[issues[i].Type] < typePriority[issues[j].Type]
		}
		return severityPriority[issues[i].Severity] < severityPriority[issues[j].Severity]
	})
}

// SearchIssues retrieves issues from SonarQube using the api/issues/search endpoint
//
// Options example:
//
//		options := map[string]string{
//	   "severities": "CRITICAL,BLOCKER",
//	   "types": "BUG",
//	   "resolved": "false",
//	   "ps": "100", // page size
//	   "p": "1",    // page number
//		}
func (c *SonarClient) SearchIssues(projectKey string, options map[string]string) (*IssuesSearchResponse, error) {
	// Construct the URL with query parameters
	baseURL := fmt.Sprintf("%s/api/issues/search", c.baseURL)
	values := url.Values{}
	values.Set("projectKeys", projectKey)

	// Add optional parameters
	for key, value := range options {
		values.Add(key, value)
	}

	// Create request
	req, err := http.NewRequest("GET", baseURL+"?"+values.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Add authentication
	req.SetBasicAuth(c.token, "")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse response
	var result IssuesSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &result, nil
}

// GetAllIssues returns all pages of issues
func (c *SonarClient) GetAllIssues(cfg *config.SrConfig) (*IssuesSearchResponse, error) {
	var issues []Issue
	var opts = map[string]string{"ps": "100", "p": "1"}
	const pageSz = 100
	var lr IssuesSearchResponse = IssuesSearchResponse{P: 1, Ps: pageSz}
	nextp := 1
	for {
		response, err := c.SearchIssues(cfg.ProjectKey, opts)
		if err != nil {
			return nil, fmt.Errorf("error searching issues at offset %d: %w", lr.P, err)
		}
		issues = append(issues, response.Issues...)
		if len(response.Issues) < pageSz {
			break
		}
		nextp += 1
		opts["p"] = fmt.Sprintf("%d", nextp)
		lr = *response
	}

	// Sort issues by type and severity
	sortIssues(issues)

	response := &IssuesSearchResponse{
		Total:  lr.Total,
		P:      lr.P,
		Ps:     lr.Ps,
		Paging: lr.Paging,
		Issues: issues,
	}

	return response, nil
}

type IssuesTemplateData struct {
	ProjectKey string
	Total      int
	P          int
	TotalPages int
	Issues     []Issue
}

// RenderIssuesTemplate renders the issues template with the provided data
func (c *SonarClient) RenderIssuesTemplate(w io.Writer, response *IssuesSearchResponse, projectKey string) error {
	// Calculate total pages
	totalPages := int(math.Ceil(float64(response.Total) / float64(response.Ps)))

	data := IssuesTemplateData{
		ProjectKey: projectKey,
		Total:      response.Total,
		P:          response.P,
		TotalPages: totalPages,
		Issues:     response.Issues,
	}

	// Parse template
	tmpl, err := template.ParseFiles(filepath.Join("templates", "issues.gohtml"))
	if err != nil {
		return err
	}

	// Execute template
	return tmpl.Execute(w, data)
}
