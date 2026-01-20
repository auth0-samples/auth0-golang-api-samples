package config

import (
	"fmt"
	"os"
)

type AuthConfig struct {
	Domain   string
	Audience string
}

func LoadAuthConfig() (*AuthConfig, error) {
	domain := os.Getenv("AUTH0_DOMAIN")
	if domain == "" {
		return nil, fmt.Errorf("AUTH0_DOMAIN environment variable required")
	}

	audience := os.Getenv("AUTH0_AUDIENCE")
	if audience == "" {
		return nil, fmt.Errorf("AUTH0_AUDIENCE environment variable required")
	}

	return &AuthConfig{
		Domain:   domain,
		Audience: audience,
	}, nil
}
