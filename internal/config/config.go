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

// DatabaseSource keeps a missing PostgreSQL DSN from falling back to a file path.
func DatabaseSource() string {
	if Env("CONNKIT_DB_DRIVER", "sqlite") == "postgres" {
		return os.Getenv("CONNKIT_DB_DSN")
	}
	return Env("CONNKIT_DB_PATH", "data/connkit.db")
}
