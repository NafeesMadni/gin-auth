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

	go func() {
		for range ticker.C {

			// We use Unscoped() to perform a 'Hard Delete' (physical removal), bypassing GORM's
			// default Soft Delete (deleted_at) to prevent the database from growing indefinitely.

			// 1. Purge Expired Sessions
			// This catches tokens that were tampered with,
			// ignored during logout, or simply left to expire.
			sessionResult := DB.Unscoped().Where("expires_at < ?", time.Now()).Delete(&models.Session{})

			// 2. Purge expired JTI entries from the Blacklist.
			// Logic: If ExpiresAt is less than the current time, the JTI is no longer
			// needed because the token would have expired naturally by now.
			blacklistResult := DB.Unscoped().Where("expires_at < ?", time.Now()).Delete(&models.Blacklist{})

			if sessionResult.RowsAffected > 0 || blacklistResult.RowsAffected > 0 {
				log.Printf("Janitor: Cleaned %d sessions and %d blacklisted tokens",
					sessionResult.RowsAffected, blacklistResult.RowsAffected)
			} else {
				log.Printf("Janitor: No expired tokens found")
			}
		}
	}()
}
