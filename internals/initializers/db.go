package initializers

import (
	"fmt"

	"gin-auth/internals/config"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ConnectToDb() {
	var err error
	dsn := config.GetEnv("DB_URL")
	fmt.Println("Connecting to database at:", dsn)

	DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to DB")
	}
}
