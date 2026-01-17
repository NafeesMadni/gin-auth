package initializers

import (
	"fmt"
	"os"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func ConnectToDb() {
	var err error
	dsn := os.Getenv("DB_URL")
	fmt.Println("Connecting to database at:", dsn)

	DB, err = gorm.Open(sqlite.Open(dsn), &gorm.Config{})

	if err != nil {
		panic("Failed to connect to DB")
	}
}
