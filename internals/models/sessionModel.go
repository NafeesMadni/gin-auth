package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	gorm.Model
	UserID       uint
	RefreshToken string `gorm:"uniqueIndex"`
	UserAgent    string // To identify the device (e.g., "Chrome on Windows")
	IPAddress    string
	ExpiresAt    time.Time `gorm:"index"`
}
