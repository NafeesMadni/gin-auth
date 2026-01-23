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

	TwoFAEnabled bool   `gorm:"column:two_fa_enabled;default:false"`
	TwoFASecret  string `gorm:"column:two_fa_secret;default:null"`
}
