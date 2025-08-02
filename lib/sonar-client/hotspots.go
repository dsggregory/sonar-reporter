package sonar_client

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// HotspotResponse represents the response from SonarQube hotspots API
type HotspotResponse struct {
	Hotspots []Hotspot `json:"hotspots"`
	Paging   Paging    `json:"paging"`
}

// Hotspot represents a security hotspot in SonarQube
type Hotspot struct {
	Key           string `json:"key"`
	Component     string `json:"component"`
	Project       string `json:"project"`
	SecurityLevel string `json:"securityLevel"`
	Status        string `json:"status"`
	Message       string `json:"message"`
	Line          int    `json:"line"`
	// error decoding response: parsing time "2025-07-25T12:01:45-0400" as "2006-01-02T15:04:05Z07:00": cannot parse "-0400" as "Z07:00"
	CreationDate CustomTime `json:"creationDate"`
	VulnRule     string     `json:"vulnerabilityProbability"`
}

// Paging represents pagination information
type Paging struct {
	PageIndex int `json:"pageIndex"`
	PageSize  int `json:"pageSize"`
	Total     int `json:"total"`
}

// GetHotspots retrieves security hotspots from SonarQube
func (c *SonarClient) GetHotspots(projectKey string) ([]Hotspot, error) {
	endpoint := fmt.Sprintf("%s/api/hotspots/search", c.baseURL)

	// Create request with query parameters
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Add query parameters
	q := url.Values{}
	q.Add("projectKey", projectKey)
	req.URL.RawQuery = q.Encode()

	// Add authentication
	req.SetBasicAuth(c.token, "")

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.responseError(resp, fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}
	// Decode response
	var hotspotResponse HotspotResponse
	if err := json.NewDecoder(resp.Body).Decode(&hotspotResponse); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return hotspotResponse.Hotspots, nil
}

// ExportHotspotsToCSV writes all hotspots to a CSV file at the specified path
func ExportHotspotsToCSV(hotspots []Hotspot, filepath string) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	headers := []string{
		"Key",
		"Component",
		"Project",
		"Security Level",
		"Status",
		"Message",
		"Line Number",
		"Creation Date",
		"Vulnerability Probability",
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("error writing CSV headers: %w", err)
	}

	// Write data rows
	for _, h := range hotspots {
		row := []string{
			h.Key,
			h.Component,
			h.Project,
			h.SecurityLevel,
			h.Status,
			h.Message,
			strconv.Itoa(h.Line),
			h.CreationDate.Format("2006-01-02 15:04:05"),
			h.VulnRule,
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("error writing hotspot row: %w", err)
		}
	}

	return nil
}

// HotspotDetail represents the detailed response from api/hotspots/show
type HotspotDetail struct {
	Key             string        `json:"key"`
	Component       Component     `json:"component"`
	Project         Project       `json:"project"`
	Rule            Rule          `json:"rule"`
	Status          string        `json:"status"`
	Line            int           `json:"line"`
	Hash            string        `json:"hash"`
	Message         string        `json:"message"`
	CreationDate    CustomTime    `json:"creationDate"`
	UpdateDate      CustomTime    `json:"updateDate"`
	TextRange       TextRange     `json:"textRange"`
	Changelog       []interface{} `json:"changelog"`
	Comments        []interface{} `json:"comment"`
	Users           []interface{} `json:"users"`
	CanChangeStatus bool          `json:"canChangeStatus"`
	Flows           []interface{} `json:"flows"`
	MessageFormats  []interface{} `json:"messageFormattings"`
}

// Component represents a SonarQube component (file, directory, etc.)
type Component struct {
	Key       string `json:"key"`
	Qualifier string `json:"qualifier"`
	Name      string `json:"name"`
	LongName  string `json:"longName"`
	Path      string `json:"path"`
}

// Project represents a SonarQube project
type Project struct {
	Key       string `json:"key"`
	Qualifier string `json:"qualifier"`
	Name      string `json:"name"`
	LongName  string `json:"longName"`
}

// Rule represents a SonarQube security rule
type Rule struct {
	Key                      string `json:"key"`
	Name                     string `json:"name"`
	SecurityCategory         string `json:"securityCategory"`
	VulnerabilityProbability string `json:"vulnerabilityProbability"`
	RiskDescription          string `json:"riskDescription"`
	VulnerabilityDescription string `json:"vulnerabilityDescription"`
	FixRecommendations       string `json:"fixRecommendations"`
}

// TextRange represents the location of the issue in the source code
type TextRange struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartOffset int `json:"startOffset"`
	EndOffset   int `json:"endOffset"`
}

// GetHotspotDetail retrieves detailed information for a single hotspot
func (c *SonarClient) GetHotspotDetail(hotspotKey string) (*HotspotDetail, error) {
	endpoint := fmt.Sprintf("%s/api/hotspots/show", c.baseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	// Add query parameters
	q := req.URL.Query()
	q.Add("hotspot", hotspotKey)
	req.URL.RawQuery = q.Encode()

	// Add authentication
	req.SetBasicAuth(c.token, "")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.responseError(resp, fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
	}

	var detail HotspotDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	return &detail, nil
}

// incrementHeaders increases HTML header levels by 1 (h1->h2, h2->h3, etc.)
func incrementHeaders(input string) string {
	re := regexp.MustCompile(`<[/]?h([1-6])>`)
	return re.ReplaceAllStringFunc(input, func(match string) string {
		level, _ := strconv.Atoi(string(match[len(match)-2]))
		if level < 6 {
			level++
		}
		if match[1] == '/' {
			return fmt.Sprintf("</h%d>", level)
		}
		return fmt.Sprintf("<h%d>", level)
	})
}

type HotspotSummary struct {
	ProjectKey string
	Total      int
}

func (c *SonarClient) RenderHotspotSummary(writer io.Writer, projectKey string, total int) error {
	data := &HotspotSummary{
		ProjectKey: projectKey,
		Total:      total,
	}
	if err := RenderTemplate(writer, "hotspots_title.gohtml", data); err != nil {
		return err
	}

	return nil
}

type HotspotsTemplateData struct {
	Detail *HotspotDetail
}

// RenderHotspots retrieves detailed information for each hotspot and writes to file
func (c *SonarClient) RenderHotspots(writer io.Writer, hotspots []Hotspot) error {
	// Parse template
	t := template.New("hotspot.gohtml").Funcs(template.FuncMap{
		"htmlSafe": func(html string) template.HTML {
			return template.HTML(html)
		},
	})
	tmpl, err := t.ParseFiles(filepath.Join("templates", "hotspot.gohtml"))
	if err != nil {
		return err
	}

	// Process each hotspot
	for i, h := range hotspots {
		detail, err := c.GetHotspotDetail(h.Key)
		if err != nil {
			return fmt.Errorf("error getting details for hotspot %s: %w", h.Key, err)
		}

		// Add a small delay to avoid overwhelming the API
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
			_, _ = fmt.Fprintln(writer, "<hr>")
		}

		detail.Rule.RiskDescription = incrementHeaders(detail.Rule.RiskDescription)
		detail.Rule.VulnerabilityDescription = incrementHeaders(detail.Rule.VulnerabilityDescription)
		data := HotspotsTemplateData{
			Detail: detail,
		}
		_ = data

		// Execute template
		if err := tmpl.Execute(writer, detail); err != nil {
			return fmt.Errorf("error executing template: %w", err)
		}
	}

	return nil
}
