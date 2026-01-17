package initializers

import (
	"gin-auth/internals/models"
	"log"
	"os"
	"strconv"
	"time"
)

func StartBlacklistCleanup() {
	cleanupIntervalStr := os.Getenv("CLEANUP_INTERVAL_MINUTES")
	cleanupInterval, err := strconv.Atoi(cleanupIntervalStr)
	if err != nil {
		cleanupInterval = 30 // Default to 30 minute if .env is missing
	}
	ticker := time.NewTicker(time.Duration(cleanupInterval) * time.Minute)

	expStr := os.Getenv("JWT_EXPIRATION_SECONDS")
	expSeconds, err := strconv.Atoi(expStr)
	if err != nil {
		expSeconds = 86400 // Default to 24 hours if .env is missing
	}

	go func() {
		for range ticker.C {
			cutoff := time.Now().Add(time.Duration(-expSeconds) * time.Second)

			// Permanent delete: By default, GORM uses Soft Deletes. If you just called .Delete(), GORM would simply put a timestamp in a deleted_at column.
			result := DB.Unscoped().Where("created_at < ?", cutoff).Delete(&models.Blacklist{})

			if result.RowsAffected > 0 {
				log.Printf("Blacklist Cleanup: Removed %d expired tokens", result.RowsAffected)
			} else {
				log.Printf("Blacklist Cleanup: No expired tokens found")
			}
		}
	}()
}
