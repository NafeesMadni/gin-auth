package models

import (
	"time"

	"gorm.io/gorm"
)

type Blacklist struct {
	gorm.Model
	Jti       string    `gorm:"column:jti;unique;index"`
	ExpiresAt time.Time `gorm:"column:expires_at;index"`
}
