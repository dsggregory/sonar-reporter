package config

import (
	"flag"
	"github.com/dsggregory/config"
	"log"
)

type SrConfig struct {
	BaseURL    string
	ProjectKey string
	SonarToken string
}

func NewSrConfig() *SrConfig {
	cfg := SrConfig{BaseURL: "http://localhost:9000"}
	if err := config.ReadConfig(&cfg); err != nil {
		log.Fatal(err)
	}

	if cfg.BaseURL == "" || cfg.ProjectKey == "" || cfg.SonarToken == "" {
		flag.Usage()
		log.Fatal("BaseURL, ProjectKey, and SonarToken must be set")
	}
	return &cfg
}
