package auth

import (
	"context"
	"fmt"
	"strings"
)

// CustomClaims contains custom data we want to parse from the JWT.
type CustomClaims struct {
	Scope string `json:"scope"`
}

// Validate ensures the custom claims are properly formatted.
func (c *CustomClaims) Validate(ctx context.Context) error {
	// Scope is optional, but if present, must be properly formatted
	if c.Scope == "" {
		return nil // No scope is valid - not all endpoints require permissions
	}

	// Validate scope format (no leading/trailing spaces, no double spaces)
	if strings.TrimSpace(c.Scope) != c.Scope {
		return fmt.Errorf("scope claim has invalid whitespace")
	}

	if strings.Contains(c.Scope, "  ") {
		return fmt.Errorf("scope claim contains double spaces")
	}

	return nil
}

// HasScope checks whether our claims have a specific scope.
func (c *CustomClaims) HasScope(expectedScope string) bool {
	if c.Scope == "" {
		return false
	}

	scopes := strings.Split(c.Scope, " ")
	for _, scope := range scopes {
		if scope == expectedScope {
			return true
		}
	}
	return false
}
