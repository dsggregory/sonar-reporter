# Sonar Scan Reporter

Create an HTML report from Sonar Scan results including Issues and Security Hotspots.

## Usage
> PROJECT_KEY=xxx SONAR_TOKEN=zzz go run main.go

The environment variables specify authentication to a sonar project. The TOKEN must be a **User-type** token and not, for instance, a Project-type token.