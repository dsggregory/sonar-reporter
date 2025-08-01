# Sonar Scan Reporter

__Currently only reports on Security Hotspots__

## Usage
> PROJECT_KEY=xxx SONAR_TOKEN=zzz go run main.go

The environment variables specify authentication to a sonar project. The TOKEN must be a **User-type** token and not, for instance, a Project-type token.