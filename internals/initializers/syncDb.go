package initializers

import (
	"gin-auth/internals/models"

	"gorm.io/gorm"
)

// Global DB variable to be used across the application
var DB *gorm.DB

func SyncDatabase() {
	err := DB.AutoMigrate(
		&models.User{},
		&models.Blacklist{},
		&models.Session{},
		&models.LoginChallenge{},
	)
	if err != nil {
		panic("Failed to migrate database")
	}
}
