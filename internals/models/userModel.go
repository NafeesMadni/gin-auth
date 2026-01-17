package models

import "gorm.io/gorm"

type User struct {
	gorm.Model        // embedding gorm.Model struct "Take everything that is inside gorm.Model and put it directly into my User struct."
	Email      string `gorm:"unique"`
	Password   string
}
