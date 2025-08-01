package config

import (
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
	return &cfg
}
