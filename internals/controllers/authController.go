package controllers

import (
	"errors"
	"gin-auth/internals/initializers"
	"gin-auth/internals/models"
	"gin-auth/internals/utils"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created"})
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}

		// Handle other possible database errors (connection lost, etc.)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Compare the provided password with the hashed password in the database
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	tokenMetadata, err := utils.GenerateAndSetToken(c, user.ID)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
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
