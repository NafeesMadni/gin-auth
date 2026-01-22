package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email         string `gorm:"uniqueIndex"`
	Password      string
	SignupID      string
	IsVerified    bool `gorm:"default:false"`
	OTPCode       string
	CodeExpiresAt time.Time

	TwoFAEnabled bool   `gorm:"default:false"`
	TwoFASecret  string `gorm:"default:null"`
}
