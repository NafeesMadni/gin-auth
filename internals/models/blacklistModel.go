package models

import (
	"time"

	"gorm.io/gorm"
)

type Blacklist struct {
	gorm.Model
	Jti       string    `gorm:"unique;index"` // The unique ID of the token
	ExpiresAt time.Time `gorm:"index"`
}
