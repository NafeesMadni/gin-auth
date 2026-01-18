package main

import (
	"gin-auth/internals/controllers"
	"gin-auth/internals/initializers"
	"gin-auth/internals/middleware"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	initializers.ConnectToDb()
	initializers.SyncDatabase()

	initializers.StartBlacklistCleanup()
}
func main() {
	r := gin.Default()

	r.POST("/signup", controllers.Signup)
	r.POST("/login", controllers.Login)
	r.POST("/logout", middleware.RequireAuth, controllers.Logout)
	r.GET("/validate", middleware.RequireAuth, controllers.Validate)

	r.GET("/auth/google/login", controllers.GoogleLogin)
	r.GET("/auth/google/callback", controllers.GoogleCallback)

	r.Run()
}
