package models

import (
	"time"

	"gorm.io/gorm"
)

// LoginChallenge manages the ephemeral state of a multi-factor login attempt.
// It enables concurrent login attempts from different devices by linking a unique ChallengeID
// to the 'Login-Session' cookie. Tracks remaining OTP attempts and enforces dual expiration
// for both the verification code and the overall challenge session.
type LoginChallenge struct {
	gorm.Model
	UserID          uint      `gorm:"column:user_id"`
	Email           string    `gorm:"column:email;index"`
	ChallengeID     string    `gorm:"column:challenge_id;uniqueIndex"` // Injected into `Login-Session` cookie
	OTPCode         string    `gorm:"column:otp_code"`
	Attempts        int       `gorm:"column:attempts;default:3"`
	CodeExpiresAt   time.Time `gorm:"column:code_expires_at;index"`
	SessionExpireAt time.Time `gorm:"column:session_expire_at;index"`
}
