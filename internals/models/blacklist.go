package models

import (
	"time"

	"gorm.io/gorm"
)

// Blacklist stores unique JWT IDs (JTI) of revoked Access tokens until their original expiry.
// This enables stateless logout by allowing middleware to intercept and reject blacklisted tokens.
// Expired entries are purged periodically to maintain optimal database performance.
type Blacklist struct {
	gorm.Model
	Jti       string    `gorm:"column:jti;unique;index"` // The unique ID of the Access token
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
}
