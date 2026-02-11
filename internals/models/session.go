package models

import (
	"time"

	"gorm.io/gorm"
)

// Session tracks active Refresh Tokens and associated device metadata.
// Used for JWT token rotation, revoking specific device access, and preventing session reuse.
type Session struct {
	gorm.Model
	UserID       uint      `gorm:"column:user_id"`
	RefreshToken string    `gorm:"column:refresh_token;uniqueIndex"`
	UserAgent    string    `gorm:"column:user_agent"` // To identify the device (e.g., "Chrome on Windows")
	IPAddress    string    `gorm:"column:ip_address"`
	ExpiresAt    time.Time `gorm:"column:expires_at;index"`
}
