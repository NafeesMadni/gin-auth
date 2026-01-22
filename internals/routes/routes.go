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

	tokenManager := utils.NewTokenManager(
		db,
		&config.CookieConfig{
			Domain:   config.GetEnvAsStr("DOMAIN", ""),
			IsSecure: config.GetEnvAsStr("SECURE_COOKIE", "true") == "true",
			HttpOnly: true, // Always HttpOnly set to true for security
		},
		JWTSecret,
		utils.CookieSetting{
			Name:   "Authorization",
			Path:   config.GetEnvAsStr("ACCESS_TOKEN_PATH", ""),
			MaxAge: config.GetEnvAsInt("ACCESS_TOKEN_EXPIRATION_SECONDS", 900, true),
		},
		utils.CookieSetting{
			Name:   "RefreshToken",
			Path:   config.GetEnvAsStr("REFRESH_TOKEN_PATH", "/auth/refresh"),
			MaxAge: config.GetEnvAsInt("REFRESH_TOKEN_EXPIRATION_SECONDS", 86400, true),
		},
		utils.CookieSetting{
			Name:   "Signup-Session",
			Path:   config.GetEnvAsStr("SIGNUP_SESSION_PATH", "/signup/otp"),
			MaxAge: config.GetEnvAsInt("SIGNUP_SESSION_EXPIRATION_SECONDS", 1800, true),
		},
		utils.CookieSetting{
			Name:   "Login-Session",
			Path:   config.GetEnvAsStr("LOGIN_SESSION_PATH", "/login/otp"),
			MaxAge: config.GetEnvAsInt("LOGIN_SESSION_EXPIRATION_SECONDS", 1800, true),
		},
	)

	// Instantiate the "Class"
	authMiddleware := middleware.NewRequireAuthMiddleware(db, tokenManager)
	googleAuthCtrl := controllers.NewGoogleAuthController(db, tokenManager)
	authCtrl := controllers.NewAuthController(db, emailManager, tokenManager)
	mfaCtrl := controllers.NewMFAController(db, tokenManager, appName, encryptionKey)
	tokenCtrl := controllers.NewTokenController(db, tokenManager)
	verifyCtrl := controllers.NewVerificationController(db, emailManager, tokenManager)

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
			// Set SIGNUP_SESSION_PATH to "/signup/otp" in your .env
			otp := signup.Group("/otp")
			{
				otp.POST("/verify", verifyCtrl.VerifySignup)
				otp.POST("/resend", verifyCtrl.ResendSignupOTP)
			}
		}
		login := public.Group("login")
		{
			login.POST("/", authCtrl.Login)

			// Verification Sub-group
			// Path Prefix: /login/otp
			// Set LOGIN_SESSION_PATH to "/login/otp" in your .env
			otp := login.Group("/otp")
			{
				otp.POST("/verify", verifyCtrl.VerifyLogin)
				otp.POST("/resend", verifyCtrl.ResendLoginOTP)
			}
		}
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
