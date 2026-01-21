package routes

import (
	"gin-auth/internals/config"
	"gin-auth/internals/controllers"
	"gin-auth/internals/middleware"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	// Load environment variables

	signup_verify_path := config.GetEnvAsStr("SIGNUP_SESSION_PATH", "/signup/otp")
	appName := config.GetEnvAsStr("APP_NAME", "Gin-Auth")
	encryptionKey := config.GetEnv("ENCRYPTION_KEY")
	JWTSecret := config.GetEnv("JWT_SECRET_KEY")

	emailManager := utils.NewEmailManager(
		&utils.SMTPConfig{
			Host:     "smtp.gmail.com",
			Port:     587,
			User:     config.GetEnv("GMAIL_USER"),
			Password: config.GetEnv("GMAIL_APP_PASSWORD"),
			AppName:  appName,
			CodeExp:  config.GetEnvAsInt("VERIFICATION_EXPIRATION_MINUTES", 10, true),
		},
	)

	// JWT & Cookie Token Manager
	tokenManager := utils.NewTokenManager(
		db,
		&config.CookieConfig{
			Domain:   config.GetEnvAsStr("DOMAIN", ""),
			IsSecure: config.GetEnvAsStr("SECURE_COOKIE", "true") == "true",
			HttpOnly: true, // Always HttpOnly set to true for security
		},
		JWTSecret,
		config.GetEnvAsInt("ACCESS_TOKEN_EXPIRATION_SECONDS", 900, true),    // Default 15 mins
		config.GetEnvAsInt("REFRESH_TOKEN_EXPIRATION_SECONDS", 86400, true), // Default 24 hours
		config.GetEnvAsStr("ACCESS_TOKEN_PATH", ""),
		config.GetEnvAsStr("REFRESH_TOKEN_PATH", "/auth/refresh"), // specific to the route path of tokenCtrl.RefreshToken endpont
	)

	// Instantiate the "Class"
	authMiddleware := middleware.NewRequireAuthMiddleware(db, JWTSecret)
	googleAuthCtrl := controllers.NewGoogleAuthController(db, tokenManager)
	authCtrl := controllers.NewAuthController(db, emailManager, tokenManager, signup_verify_path)
	mfaCtrl := controllers.NewMFAController(db, tokenManager, appName, encryptionKey)
	tokenCtrl := controllers.NewTokenController(db, tokenManager)
	verifyCtrl := controllers.NewVerificationController(db, emailManager)

	public := r.Group("/")
	{
		public.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"status":      "active",
				"environment": "development",
				"message":     "Gin-Auth API is running",
			})
		})
		signup := public.Group("signup")
		{
			// Path: /signup (No cookie sent here)
			signup.POST("/", authCtrl.Signup)

			// Verification Sub-group
			// Path Prefix: /signup/otp
			// Set SignupPath to "/signup/otp" in your .env
			otp := signup.Group("/otp")
			{
				otp.POST("/verify", verifyCtrl.VerifyEmail)
				otp.POST("/resend", verifyCtrl.ResendVerificationCode)
			}
		}
		public.POST("/login", authCtrl.Login)
		public.POST("/request-login-otp", authCtrl.RequestLoginCode)
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
