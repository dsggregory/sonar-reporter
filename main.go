package main

import (
	sonar_client "SonarReporter/lib/sonar-client"
	"log"
	"os"
)

//TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>

func main() {
	client := sonar_client.NewSonarClient("http://localhost:9000", os.Getenv("SONAR_TOKEN"))

	hotspots, err := client.GetHotspots(os.Getenv("PROJECT_KEY"))
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Export detailed information to CSV
	fname := "detailed_security_hotspots.csv"
	if err := client.ExportDetailedHotspots(hotspots, "detailed_security_hotspots.html"); err != nil {
		log.Fatalf("Failed to export detailed hotspots to HTML: %v", err)
	}

	log.Println("Successfully exported hotspots to", fname)
	log.Println(
		"You can view the detailed hotspots in your browser by opening",
		fname,
		"or by running the following command:",
		"open", fname,
	)
}
