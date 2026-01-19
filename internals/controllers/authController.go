package controllers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"gin-auth/internals/initializers"
	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Validate(c *gin.Context) {
	// get user from context (which was set in middleware)
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": "You are logged in!",
		"user":    user,
	})
}

func Signup(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	existingUser := models.User{}
	if err := initializers.DB.Where("email = ?", body.Email).First(&existingUser).Error; err == nil {
		if existingUser.IsVerified {
			c.JSON(http.StatusConflict, gin.H{"error": "This email is already registered. Please log in."})
			return
		} else {
			c.JSON(http.StatusConflict, gin.H{"error": "You are already registered. Please check your email to verify your account."})
			return
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}

	code := utils.GenerateVerificationCode()
	expirationMinutes := utils.GetVerificationExpirationMinutes()

	newUser := models.User{
		Email:            body.Email,
		Password:         string(hash),
		VerificationCode: code,
		CodeExpiresAt:    time.Now().Add(time.Duration(expirationMinutes) * time.Minute),
	}

	result := initializers.DB.Create(&newUser)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	// Send the email in a background goroutine so the response isn't slow
	go utils.SendVerificationEmail(newUser.Email, code)

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Please check your email for the verification code. The code will expires in %d minutes.", expirationMinutes)})
}

func VerifyEmail(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	var user models.User
	if err := initializers.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
		return
	}

	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	// Check if expired
	if time.Now().After(user.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code expired"})
		return
	}

	if user.VerificationCode != body.Code {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// Mark as verified
	initializers.DB.Model(&user).Updates(map[string]interface{}{
		"IsVerified":       true,
		"VerificationCode": "", // Clear the code after use
	})

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func ResendVerificationCode(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required,email"`
	}

	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	var user models.User
	if err := initializers.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		// Security: Use a generic success message to prevent account enumeration
		// This way, attackers cannot determine if an email is registered or not
		c.JSON(http.StatusOK, gin.H{"message": "If this email is registered, a new code has been sent."})
		return
	}

	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account is already verified"})
		return
	}

	// --- COOLDOWN LOGIC ---
	// Check if the last code was sent less than 1 minute ago
	if time.Now().Before(user.UpdatedAt.Add(1 * time.Minute)) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Please wait a minute before requesting a new code"})
		return
	}

	newCode := utils.GenerateVerificationCode()
	expirationMinutes := utils.GetVerificationExpirationMinutes()

	initializers.DB.Model(&user).Updates(models.User{
		VerificationCode: newCode,
		CodeExpiresAt:    time.Now().Add(time.Duration(expirationMinutes) * time.Minute),
	})

	go utils.SendVerificationEmail(user.Email, newCode)

	c.JSON(http.StatusOK, gin.H{"message": "A new verification code has been sent to your email"})
}

func Setup2FA(c *gin.Context) {
	// get user from context (which was set in middleware)
	user, _ := c.Get("user")
	u := user.(models.User)

	// Generate a new TOTP Key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      os.Getenv("APP_NAME"),
		AccountName: u.Email,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate 2FA key"})
		return
	}

	encrypted_secret, err := utils.Encrypt(key.Secret())
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to encrypt 2FA secret"})
		return
	}

	// Save the Secret to the user's record
	initializers.DB.Model(&u).Update("TwoFASecret", encrypted_secret)

	// Generate QR Code as a Base64 image
	img, _ := key.Image(200, 200)
	var buf bytes.Buffer
	png.Encode(&buf, img)
	imgBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	c.JSON(200, gin.H{
		"secret":      key.Secret(),
		"qr_code_url": "data:image/png;base64," + imgBase64,
	})
}

func Activate2FA(c *gin.Context) {
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	c.Bind(&body)

	// get user from context (which was set in middleware)
	user, _ := c.Get("user")
	u := user.(models.User)

	decryptedSecret, err := utils.Decrypt(u.TwoFASecret)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to decrypt 2FA secret"})
		return
	}

	if !utils.Validate2FA(body.Code, decryptedSecret) {
		c.JSON(400, gin.H{"error": "Invalid verification code"})
		return
	}

	initializers.DB.Model(&u).Update("TwoFAEnabled", true)
	c.JSON(200, gin.H{"message": "2FA activated successfully"})
}

func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	c.Bind(&body)

	var user models.User // initialize an empty user struct with values set to their zero values

	result := initializers.DB.Where("email = ?", body.Email).First(&user)

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
	tokenMetadata, err := utils.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
}

func LoginVerify2FA(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required"`
		Code  string `json:"code" binding:"required"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and Code are required"})
		return
	}

	var user models.User
	if err := initializers.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if !user.TwoFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2FA is not enabled for this account"})
		return
	}

	// Decrypt the stored TOTP secret
	decryptedSecret, err := utils.Decrypt(user.TwoFASecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process security key"})
		return
	}

	if !utils.Validate2FA(body.Code, decryptedSecret) {
		c.JSON(400, gin.H{"error": "Invalid verification code"})
		return
	}

	// Success! Create the final session and set JWT cookies
	tokenMetadata, err := utils.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "You'r verified, logged in successfully.", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
}

func Logout(c *gin.Context) {
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
		initializers.DB.Unscoped().Where("refresh_token = ?", reftokenStr).Delete(&models.Session{})
	}

	// Blacklist the access token
	if acctokenStr != "" {
		token, _ := jwt.Parse(acctokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("SECRET")), nil
		})

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if jti, ok := claims["jti"].(string); ok {

				// In jwt-go, numbers are parsed as float64 by default
				var expireAt time.Time
				if exp, ok := claims["exp"].(float64); ok {
					expireAt = time.Unix(int64(exp), 0)
				} else {
					expSeconds, err := strconv.Atoi(os.Getenv("JWT_EXPIRATION_SECONDS"))
					if err != nil {
						expSeconds = 86400 // Default to 24 hours if .env is missing
					}
					// Fallback: If exp is missing, set a safe default (e.g., 24 hours from now)
					expireAt = time.Now().Add(time.Duration(expSeconds) * time.Second)
				}

				// 2. Create the Blacklist entry with the expiration date
				initializers.DB.Create(&models.Blacklist{
					Jti:       jti,
					ExpiresAt: expireAt,
				})
			}
		}
	}
	utils.SetClearCookies(c)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func RefreshToken(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("RefreshToken")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Find the session in the DB
	var session models.Session
	if err := initializers.DB.Where("refresh_token = ?", refreshTokenStr).First(&session).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found or revoked"})
		return
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		initializers.DB.Unscoped().Delete(&session) // Clean up expired session
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		return
	}

	// ROTATION: Delete the old session and create a new one
	initializers.DB.Unscoped().Delete(&session)

	tokens, err := utils.GenerateAndSetToken(c, session.UserID)
	if err != nil {
		log.Printf("Rotation Failure for User %d: %v", session.UserID, err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Session rotation failed. Please log in again.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed", "access_token": tokens.AccessToken})
}
