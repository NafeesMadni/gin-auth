package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthController struct {
	DB           *gorm.DB
	EmailManager *utils.EmailManager
	TokenManager *utils.TokenManager
}

func NewAuthController(db *gorm.DB, emailManager *utils.EmailManager, tokenManager *utils.TokenManager) *AuthController {
	return &AuthController{
		DB:           db,
		EmailManager: emailManager,
		TokenManager: tokenManager,
	}
}

func (a *AuthController) Signup(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	existingUser := models.User{}
	if err := a.DB.Where("email = ?", body.Email).First(&existingUser).Error; err == nil {
		if existingUser.IsVerified {
			c.JSON(http.StatusConflict, gin.H{"error": "This email is already registered. Please log in."})
			return
		}
		// If the user exists but is unverified, delete the existing record to allow re-signup
		a.DB.Unscoped().Delete(&existingUser)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}

	signupID := uuid.New().String() // Unique ID for specific attempt
	otpCode := a.EmailManager.GenerateVerificationCode()
	expMinutes := a.EmailManager.Config.CodeExp

	newUser := models.User{
		Email:         body.Email,
		Password:      string(hash),
		SignupID:      signupID,
		OTPCode:       otpCode,
		CodeExpiresAt: time.Now().Add(time.Duration(expMinutes) * time.Minute),
	}

	result := a.DB.Create(&newUser)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	// Set a "Signup-Session" cookie in the user's browser
	a.TokenManager.SetSignupSession(c, signupID)

	// Send the email in a background goroutine so the response isn't slow
	go a.EmailManager.SendSignupOTP(newUser.Email, otpCode)

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Please check your email for the verification code. The code will expires in %d minutes.", expMinutes), "signup_session": signupID})
}

func (a *AuthController) Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	c.Bind(&body)

	var user models.User // initialize an empty user struct with values set to their zero values

	result := a.DB.Where("email = ?", body.Email).First(&user)

	if result.Error != nil {
		// Specifically check if the error is "Record Not Found"
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Please enter a valid email address"})
			return
		}

		// Handle other possible database errors (connection lost, etc.)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Compare the provided password with the hashed password in the database
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Please enter a valid password"})
		return
	}

	if !user.IsVerified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email is not verified"})
		return
	}

	// --- 2FA CHECK ---
	if user.TwoFAEnabled {
		// Return a 200 OK but with a flag indicating MFA is needed
		// No session or cookies are created yet
		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"email":        user.Email,
			"message":      "Please enter your 2FA code to continue",
		})
		return
	}

	// Standard Login (No 2FA): Create Session & Set Cookies
	tokenMetadata, err := a.TokenManager.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
}

func (a *AuthController) RequestLoginCode(c *gin.Context) {
	var body struct {
		Email string
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}
	var user models.User
	err := a.DB.Where("email = ?", body.Email).First(&user).Error

	// To prevent user enumeration, we will always return a success-like response.
	// The actual OTP generation and sending will only happen if the user exists and is verified.
	challengeID := uuid.New().String()
	codeExpAt := a.EmailManager.Config.CodeExp

	if err == nil && user.IsVerified {
		otpCode := a.EmailManager.GenerateVerificationCode()

		lc := models.LoginChallenge{
			UserID:          user.ID,
			Email:           body.Email,
			ChallengeID:     challengeID,
			OTPCode:         otpCode,
			CodeExpiresAt:   time.Now().Add(time.Duration(codeExpAt) * time.Minute),
			SessionExpireAt: time.Now().Add(time.Duration(a.TokenManager.Login.MaxAge) * time.Minute),
		}

		if dbErr := a.DB.Create(&lc).Error; dbErr != nil {
			// Use a more specific error message and appropriate status code.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create login challenge"})
			return
		}

		go a.EmailManager.SendLoginOTP(lc.Email, otpCode)
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		// A real database error occurred, other than not finding the user.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	// For non-existent or unverified users, we proceed without creating a DB record or sending an email.
	// The subsequent OTP verification will fail because the challengeID won't be found in the database, which is the desired behavior.

	a.TokenManager.SetLoginSession(c, challengeID)

	c.JSON(http.StatusOK, gin.H{
		"message":       fmt.Sprintf("If an account with email %s exists, a verification code has been sent. It expires in %d minutes.", body.Email, codeExpAt),
		"login_session": challengeID,
	})
}

func (a *AuthController) Logout(c *gin.Context) {
	acctokenStr, accErr := c.Cookie("Authorization")
	reftokenStr, refErr := c.Cookie("RefreshToken")

	// If both are missing, the user is already "logged out"
	if accErr != nil && refErr != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Already logged out"})
		return
	}

	// 1. Target the session for immediate revocation via the Refresh Token string.
	// 2. Fallback Logic: If the token is invalid/tampered, the query fails to find a match.
	// 3. Fail-safe: The Background Janitor acts as the ultimate source of truth,
	//    deleting any session by expiration date, regardless of the token's validity.
	if reftokenStr != "" {
		// Unscoped(): permanently remove the session record
		a.DB.Unscoped().Where("refresh_token = ?", reftokenStr).Delete(&models.Session{})
	}

	// Blacklist the access token
	if acctokenStr != "" {
		token, _ := jwt.Parse(acctokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(a.TokenManager.JWTSecret), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if jti, ok := claims["jti"].(string); ok {

				// In jwt-go, numbers are parsed as float64 by default
				var expireAt time.Time
				if exp, ok := claims["exp"].(float64); ok {
					expireAt = time.Unix(int64(exp), 0)
				} else {
					expSeconds := a.TokenManager.Access.MaxAge
					expireAt = time.Now().Add(time.Duration(expSeconds) * time.Second)
				}

				// 2. Create the Blacklist entry with the expiration date
				a.DB.Create(&models.Blacklist{
					Jti:       jti,
					ExpiresAt: expireAt,
				})
			}
		}
	}
	a.TokenManager.ClearJWTCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}
