package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email         string    `gorm:"column:email;uniqueIndex"`
	Password      string    `gorm:"column:password"`
	SignupID      string    `gorm:"column:signup_id"`
	IsVerified    bool      `gorm:"column:is_verified;default:false"`
	OTPCode       string    `gorm:"column:otp_code"`
	CodeExpiresAt time.Time `gorm:"column:code_expires_at"`

	// Multi-Factor Authentication
	TwoFAEnabled bool   `gorm:"column:two_fa_enabled;default:false"`
	TwoFASecret  string `gorm:"column:two_fa_secret;default:null"`

	// OAuth2 / Social Login
	GoogleID string `gorm:"column:google_id;uniqueIndex"`
	Avatar   string `gorm:"column:avatar"`
	FullName string `gorm:"column:full_name"`
}
