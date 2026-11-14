// Package config reads process configuration from the environment.
package config

import "os"

// Env returns the configured value or a default.
func Env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
