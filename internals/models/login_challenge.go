package models

import (
	"time"

	"gorm.io/gorm"
)

type LoginChallenge struct {
	gorm.Model
	Email         string `gorm:"index"`
	ChallengeID   string `gorm:"uniqueIndex"` // Injected into Login-Session cookie
	OTPCode       string
	Attempts      int       `gorm:"default:3"`
	CodeExpiresAt time.Time `gorm:"index"`
}
