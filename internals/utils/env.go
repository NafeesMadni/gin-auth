package utils

import (
	"os"
	"strconv"
)

// GetEnv fetches a key or returns a default value
func GetEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func GetEnvAsInt(key string, fallback int, checkLess bool) int {
	if valueStr, ok := os.LookupEnv(key); ok {
		if value, err := strconv.Atoi(valueStr); err == nil {
			if checkLess && value <= 0 {
				return fallback
			}
			return value
		}
	}
	return fallback
}
