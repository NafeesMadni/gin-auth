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

	public := r.Group("/")
	{
		public.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status":      "active",
				"environment": "development",
				"message":     "Gin-Auth API is running",
			})
		})
		r.POST("/signup", controllers.Signup)
		r.POST("/login", controllers.Login)
	}

	protected := r.Group("/")
	protected.Use(middleware.RequireAuth)
	{
		protected.POST("/logout", controllers.Logout)
		protected.GET("/validate", controllers.Validate)
	}

	auth := r.Group("/auth")
	{
		auth.POST("/refresh", controllers.RefreshToken)
		auth.GET("/google/login", controllers.GoogleLogin)
		auth.GET("/google/callback", controllers.GoogleCallback)
	}

	r.Run()
}
