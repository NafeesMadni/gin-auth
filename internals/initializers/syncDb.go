package initializers

import (
	"gin-auth/internals/models"

	"gorm.io/gorm"
)

// Global DB variable to be used across the application
var DB *gorm.DB

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
