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

	//body, err := ioutil.ReadAll(resp.Body)
	//print(body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
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
/*
{
  "key" : "AZhCUvjRhaoHRbtrKnH3",
  "component" : {
    "key" : "CheddarAll:backend/api/config/initializers/constants.rb",
    "qualifier" : "FIL",
    "name" : "constants.rb",
    "longName" : "backend/api/config/initializers/constants.rb",
    "path" : "backend/api/config/initializers/constants.rb"
  },
  "project" : {
    "key" : "CheddarAll",
    "qualifier" : "TRK",
    "name" : "CheddarAll",
    "longName" : "CheddarAll"
  },
  "rule" : {
    "key" : "ruby:S2068",
    "name" : "Hard-coded credentials are security-sensitive",
    "securityCategory" : "auth",
    "vulnerabilityProbability" : "HIGH",
    "riskDescription" : "<p>Because it is easy to extract strings from an application source code or binary, credentials should not be hard-coded. This is particularly true\nfor applications that are distributed or that are open-source.</p>\n<p>In the past, it has led to the following vulnerabilities:</p>\n<ul>\n  <li> <a href=\"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-13466\">CVE-2019-13466</a> </li>\n  <li> <a href=\"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15389\">CVE-2018-15389</a> </li>\n</ul>\n<p>Credentials should be stored outside of the code in a configuration file, a database, or a management service for secrets.</p>\n<p>This rule flags instances of hard-coded credentials used in database and LDAP connections. It looks for hard-coded credentials in connection\nstrings, and for variable names that match any of the patterns from the provided list.</p>\n<p>It’s recommended to customize the configuration of this rule with additional credential words such as \"oauthToken\", \"secret\", …​</p>\n",
    "vulnerabilityDescription" : "<h2>Ask Yourself Whether</h2>\n<ul>\n  <li> Credentials allow access to a sensitive component like a database, a file storage, an API or a service. </li>\n  <li> Credentials are used in production environments. </li>\n  <li> Application re-distribution is required before updating the credentials. </li>\n</ul>\n<p>There is a risk if you answered yes to any of those questions.</p>\n",
    "fixRecommendations" : "<h2>Recommended Secure Coding Practices</h2>\n<ul>\n  <li> Store the credentials in a configuration file that is not pushed to the code repository. </li>\n  <li> Store the credentials in a database. </li>\n  <li> Use your cloud provider’s service for managing secrets. </li>\n  <li> If a password has been disclosed through the source code: change it. </li>\n</ul>\n<h2>See</h2>\n<ul>\n  <li> <a href=\"https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/\">OWASP Top 10 2021 Category A7</a> - Identification and\n  Authentication Failures </li>\n  <li> <a href=\"https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication\">OWASP Top 10 2017 Category A2</a> - Broken Authentication\n  </li>\n  <li> <a href=\"https://cwe.mitre.org/data/definitions/798\">MITRE, CWE-798</a> - Use of Hard-coded Credentials </li>\n  <li> <a href=\"https://cwe.mitre.org/data/definitions/259\">MITRE, CWE-259</a> - Use of Hard-coded Password </li>\n  <li> <a href=\"https://www.sans.org/top25-software-errors/#cat3\">SANS Top 25</a> - Porous Defenses </li>\n  <li> Derived from FindSecBugs rule <a href=\"https://h3xstream.github.io/find-sec-bugs/bugs.htm#HARD_CODE_PASSWORD\">Hard Coded Password</a> </li>\n</ul>"
  },
  "status" : "TO_REVIEW",
  "line" : 2,
  "hash" : "658b5e333cb83fce1e34e649832c2f8b",
  "message" : "\"PASSWORD\" detected here, make sure this is not a hard-coded credential.",
  "creationDate" : "2025-07-25T12:01:45-0400",
  "updateDate" : "2025-07-25T12:01:45-0400",
  "textRange" : {
    "startLine" : 2,
    "endLine" : 2,
    "startOffset" : 0,
    "endOffset" : 13
  },
  "changelog" : [ ],
  "comment" : [ ],
  "users" : [ ],
  "canChangeStatus" : true,
  "flows" : [ ],
  "messageFormattings" : [ ]
}
*/
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

	//body, err := ioutil.ReadAll(resp.Body)
	//print(body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
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
