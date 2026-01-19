package initializers

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

func LoadEnvVariables() {
	// Check if .env exists before trying to load it
	// This prevents the app from crashing in production environments (Docker/K8s)
	// where env vars are injected directly and .env isn't used.
	if _, err := os.Stat(".env"); err == nil {
		err := godotenv.Load()
		if err != nil {
			log.Fatal("Error loading .env file")
		}
	}
}
