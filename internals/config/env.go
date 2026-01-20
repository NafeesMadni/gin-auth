package config

import (
	"log"
	"os"
	"strconv"
)

// GetEnv fetches a key or returns an empty string
// Critical env vars should use this function
func GetEnv(key string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("Critical: Environment variable %s not set\n", key)
	return ""
}

// GetEnvAsStr fetches a key or returns a fallback value
// Useful for non-critical env vars
func GetEnvAsStr(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	log.Printf("Warning: Environment variable %s not set, using fallback value\n", key)
	return fallback
}

// GetEnvAsInt fetches a key as integer, compares it with a ensurePositive flag, or returns a fallback value
func GetEnvAsInt(key string, fallback int, ensurePositive bool) int {
	if valueStr, ok := os.LookupEnv(key); ok {
		if value, err := strconv.Atoi(valueStr); err == nil {
			if ensurePositive && value <= 0 {
				log.Printf("Warning: Environment variable %s is not positive, using fallback value\n", key)
				return fallback
			}
			return value
		}
	}
	log.Printf("Warning: Environment variable %s not set, using fallback value\n", key)
	return fallback
}
