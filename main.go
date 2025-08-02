package main

import (
	"SonarReporter/lib/config"
	sonar_client "SonarReporter/lib/sonar-client"
	"fmt"
	"log"
	"os"
)

func main() {
	cfg := config.NewSrConfig()
	client := sonar_client.NewSonarClient(cfg.BaseURL, cfg.SonarToken)

	// Create output file
	fp, err := os.Create(fmt.Sprintf("sonar-report-%s.html", cfg.ProjectKey))
	if err != nil {
		log.Fatal(err)
	}
	defer fp.Close()

	if err := sonar_client.RenderHtmlHead(fp); err != nil {
		log.Fatal(err)
	}

	// Render Issues
	response, err := client.GetAllIssues(cfg)
	if err := client.RenderIssuesTemplate(fp, response, cfg.ProjectKey); err != nil {
		log.Fatal(err)
	}

	// Render Security Hotspots
	hotspots, err := client.GetHotspots(cfg.ProjectKey)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// Summary
	if err := client.RenderHotspotSummary(fp, cfg.ProjectKey, len(hotspots)); err != nil {
		log.Fatalf("Failed to export hotspot summary to HTML: %v", err)
	}
	// Export detailed information to running HTML
	if err := client.RenderHotspots(fp, hotspots); err != nil {
		log.Fatalf("Failed to export detailed hotspots to HTML: %v", err)
	}

	if err := sonar_client.RenderHtmlTail(fp); err != nil {
		log.Fatal(err)
	}

	log.Println("Successfully exported issues and hotspots to", fp.Name())
	log.Println(
		"You can view the report in your browser by opening",
		fp.Name(),
		"or by running the following command:",
		"open", fp.Name(),
	)
}
