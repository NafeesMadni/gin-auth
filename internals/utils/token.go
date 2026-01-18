package utils

import (
	"fmt"
	"gin-auth/internals/initializers"
	"gin-auth/internals/models"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func GetDefaultCookieConfigs() (CookieConfig, CookieConfig) {
	// Check if we are in production/secure mode
	isSecure := os.Getenv("COOKIE_SECURE") == "true"

	acc := CookieConfig{Secure: isSecure}
	ref := CookieConfig{Path: "/auth/refresh", Secure: isSecure}
	return acc, ref
}

func SetClearCookies(c *gin.Context) {
	accConfig, refConfig := GetDefaultCookieConfigs()
	c.SetCookie("Authorization", "", -1, accConfig.Path, accConfig.Domain, accConfig.Secure, accConfig.HttpOnly)
	c.SetCookie("RefreshToken", "", -1, refConfig.Path, refConfig.Domain, refConfig.Secure, refConfig.HttpOnly)
}

func createAccessToken(UserID uint, accExpiresAt time.Time) (string, error) {
	accessTokenID := uuid.New().String()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"jti": accessTokenID,
		"exp": accExpiresAt.Unix(),
	})

	return accessToken.SignedString([]byte(os.Getenv("SECRET")))
}

func createRefreshToken(UserID uint, refExpiresAt time.Time) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"exp": refExpiresAt.Unix(),
	})

	return refreshToken.SignedString([]byte(os.Getenv("SECRET")))
}

// GenerateAndSetToken generates access and refresh tokens and sets the access token in a cookie
func GenerateAndSetToken(
	c *gin.Context,
	UserID uint,
) (*TokenMetadata, error) {

	accExp, err := strconv.Atoi(os.Getenv("JWT_EXPIRATION_SECONDS"))
	// If .env var is empty then strconv.Atoi places 0 by default
	if err != nil || accExp <= 0 {
		// To prevent an immediate logout, set value to 15 minutes
		accExp = 900
	} // Default 15 mins

	refExp, err := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION_SECONDS"))
	if err != nil || refExp <= 0 {
		refExp = 86400
	} // Default 24 hours

	accExpiresAt := time.Now().Add(time.Duration(accExp) * time.Second)
	refExpiresAt := time.Now().Add(time.Duration(refExp) * time.Second)

	// Create tokens
	accTokenStr, accErr := createAccessToken(UserID, accExpiresAt)
	refTokenStr, refErr := createRefreshToken(UserID, refExpiresAt)

	if accErr != nil || refErr != nil {
		// CLEANUP: If token generation fails, clear whatever is currently in the browser if call for cookie rotation
		SetClearCookies(c)
		return nil, fmt.Errorf("token generation failed")
	}

	session := models.Session{
		UserID:       UserID,
		RefreshToken: refTokenStr,
		UserAgent:    c.Request.UserAgent(),
		IPAddress:    c.ClientIP(),
		ExpiresAt:    refExpiresAt,
	}

	if err := initializers.DB.Create(&session).Error; err != nil {
		// CLEANUP: If DB fails, we must not leave the user with "half-valid" state
		SetClearCookies(c)
		return nil, err
	}

	accConfig, refConfig := GetDefaultCookieConfigs()

	// Set secure cookies
	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie("Authorization", accTokenStr, accExp, accConfig.Path, accConfig.Domain, accConfig.Secure, accConfig.HttpOnly)
	c.SetCookie("RefreshToken", refTokenStr, refExp, refConfig.Path, refConfig.Domain, refConfig.Secure, refConfig.HttpOnly)

	return &TokenMetadata{AccessToken: accTokenStr, RefreshToken: refTokenStr}, nil
}
