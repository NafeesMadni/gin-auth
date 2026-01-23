package models

import (
	"time"

	"gorm.io/gorm"
)

type Session struct {
	gorm.Model
	UserID       uint      `gorm:"column:user_id"`
	RefreshToken string    `gorm:"column:refresh_token;uniqueIndex"`
	UserAgent    string    `gorm:"column:user_agent"`
	IPAddress    string    `gorm:"column:ip_address"`
	ExpiresAt    time.Time `gorm:"column:expires_at;index"`
}
