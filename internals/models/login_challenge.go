package models

import (
	"time"

	"gorm.io/gorm"
)

type LoginChallenge struct {
	gorm.Model
	UserID          uint      `gorm:"column:user_id"`
	Email           string    `gorm:"column:email;index"`
	ChallengeID     string    `gorm:"column:challenge_id;uniqueIndex"` // Injected into Login-Session cookie
	OTPCode         string    `gorm:"column:otp_code"`
	Attempts        int       `gorm:"column:attempts;default:3"`
	CodeExpiresAt   time.Time `gorm:"column:code_expires_at;index"`
	SessionExpireAt time.Time `gorm:"column:session_expire_at;index"`
}
