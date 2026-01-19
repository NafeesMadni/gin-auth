package routes

import (
	"os"

	"gin-auth/internals/controllers"
	"gin-auth/internals/middleware"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	smtpSettings := &utils.SMTPConfig{
		Host:     "smtp.gmail.com",
		Port:     587,
		User:     os.Getenv("GMAIL_USER"),
		Password: os.Getenv("GMAIL_APP_PASSWORD"),
		AppName:  utils.GetEnv("APP_NAME", "Gin-Auth"),
		CodeExp:  utils.GetEnvAsInt("VERIFICATION_EXPIRATION_MINUTES", 10, true),
	}

	jwtSecret := os.Getenv("JWT_SECRET_KEY")

	// Instantiate the "Class"
	authMiddleware := middleware.NewRequireAuthMiddleware(db, jwtSecret)

	googleAuthCtrl := controllers.NewGoogleAuthController(db, jwtSecret)
	authCtrl := controllers.NewAuthController(db, smtpSettings, jwtSecret)
	mfaCtrl := controllers.NewMFAController(db, jwtSecret)
	tokenCtrl := controllers.NewTokenController(db, jwtSecret)
	verifyCtrl := controllers.NewVerificationController(db, smtpSettings)

	public := r.Group("/")
	{
		public.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status":      "active",
				"environment": "development",
				"message":     "Gin-Auth API is running",
			})
		})
		public.POST("/signup", authCtrl.Signup)
		public.POST("/verify", verifyCtrl.VerifyEmail)
		public.POST("/resend-code", verifyCtrl.ResendVerificationCode)
		public.POST("/login", authCtrl.Login)
		public.POST("/2fa/login-verify", mfaCtrl.LoginVerify2FA)
	}

	protected := r.Group("/")
	protected.Use(authMiddleware.RequireAuth)
	{
		protected.POST("/logout", authCtrl.Logout)
		protected.GET("/validate", tokenCtrl.Validate)

		protected.POST("/2fa/setup", mfaCtrl.Setup2FA)
		protected.POST("/2fa/activate", mfaCtrl.Activate2FA)
	}

	auth := r.Group("/auth")
	{
		auth.POST("/refresh", tokenCtrl.RefreshToken)
		auth.GET("/google/login", googleAuthCtrl.Login)
		auth.GET("/google/callback", googleAuthCtrl.Callback)
	}
	return r
}
