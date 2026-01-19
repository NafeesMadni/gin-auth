package routes

import (
	"gin-auth/internals/controllers"
	"gin-auth/internals/middleware"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	// Instantiate the "Class"
	authCtrl := controllers.NewGoogleAuthController(db)

	public := r.Group("/")
	{
		public.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status":      "active",
				"environment": "development",
				"message":     "Gin-Auth API is running",
			})
		})
		public.POST("/signup", controllers.Signup)
		public.POST("/verify", controllers.VerifyEmail)
		public.POST("/resend-code", controllers.ResendVerificationCode)
		public.POST("/login", controllers.Login)
		public.POST("/2fa/login-verify", controllers.LoginVerify2FA)
	}

	protected := r.Group("/")
	protected.Use(middleware.RequireAuth)
	{
		protected.POST("/logout", controllers.Logout)
		protected.GET("/validate", controllers.Validate)

		protected.POST("/2fa/setup", controllers.Setup2FA)
		protected.POST("/2fa/activate", controllers.Activate2FA)
	}

	auth := r.Group("/auth")
	{
		auth.POST("/refresh", controllers.RefreshToken)
		auth.GET("/google/login", authCtrl.Login)
		auth.GET("/google/callback", authCtrl.Callback)
	}
	return r
}
