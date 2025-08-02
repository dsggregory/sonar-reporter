# Sonar Scan Reporter

Create an HTML report from Sonar Scan results including Issues and Security Hotspots.

## Usage
```aiignore
Usage of SonarReporter:
  -base-url string
         (default "http://localhost:9000")
  -project-key string
        
  -sonar-token string
```

Example:
  > PROJECT_KEY=xxx SONAR_TOKEN=zzz go run main.go

The environment variables specify authentication to a sonar project. The TOKEN must be a **User-type** token and not, for instance, a Project-type token.

## References
* [SonarQube API](https://next.sonarqube.com/sonarqube/web_api/api/issues)
