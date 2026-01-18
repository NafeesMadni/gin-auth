package utils

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GenerateAndSetToken(c *gin.Context, UserID uint) (string, error) {

	expStr := os.Getenv("JWT_EXPIRATION_SECONDS")
	expSeconds, err := strconv.Atoi(expStr)
	if err != nil {
		expSeconds = 86400 // Default to 24 hours if .env is missing
	}

	tokenID := uuid.New().String()

	// Create JWT Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"jti": tokenID,
		"exp": time.Now().Add(time.Duration(expSeconds) * time.Second).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return "", err
	}

	// Set Cookie (Optional but recommended for browsers)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, expSeconds, "", "", false, true) // set secure to true in production

	return tokenString, nil
}
