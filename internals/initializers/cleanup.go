package initializers

import (
	"log"
	"time"

	"gin-auth/internals/config"
	"gin-auth/internals/models"
)

func StartBlacklistCleanup() {
	cleanupInterval := config.GetEnvAsInt("CLEANUP_INTERVAL_MINUTES", 30, true)
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

			// 3. Purge unverified users older than a certain threshold (e.g., 24 Hours)
			userResult := DB.Unscoped().Where("is_verified = ? AND created_at < ?", false, time.Now().Add(-24*time.Hour)).Delete(&models.User{})

			// 4. Purge Expired Login Challenges
			// Logic: Once CodeExpiresAt is past, the challenge is useless and cannot be verified.
			challengeResult := DB.Unscoped().Where("session_expire_at < ?", time.Now()).Delete(&models.LoginChallenge{})

			if sessionResult.RowsAffected > 0 || blacklistResult.RowsAffected > 0 || userResult.RowsAffected > 0 || challengeResult.RowsAffected > 0 {
				log.Printf("Janitor: Cleaned %d sessions, %d blacklisted tokens, %d unverified users, and %d login challenges",
					sessionResult.RowsAffected, blacklistResult.RowsAffected, userResult.RowsAffected, challengeResult.RowsAffected)
			} else {
				log.Printf("Janitor: No expired tokens found")
			}
		}
	}()
}
