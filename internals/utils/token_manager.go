package utils

import (
	"fmt"
	"net/http"
	"time"

	"gin-auth/internals/config"
	"gin-auth/internals/initializers"
	"gin-auth/internals/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// CookieConfig groups settings for cleaner function signatures
type CookieConfig struct {
	Path     string `default:""`      // Path: e.g., "/", "/auth/refresh"
	Domain   string `default:""`      // Domain: Set to your domain, e.g., "example.com"
	Secure   bool   `default:"false"` // Secure: Set to true if using HTTPS
	HttpOnly bool   `default:"true"`  // HttpOnly: CRITICAL for XSS protection - Always true
}

// TokenMetadata holds the results of token generation
type TokenMetadata struct {
	AccessToken  string
	RefreshToken string
}

func GetDefaultCookieConfigs() (CookieConfig, CookieConfig) {
	// Check if we are in production/secure mode
	isSecure := config.GetEnv("COOKIE_SECURE") == "true"

	acc := CookieConfig{Secure: isSecure}
	ref := CookieConfig{Path: "/auth/refresh", Secure: isSecure}
	return acc, ref
}

func SetClearCookies(c *gin.Context) {
	accConfig, refConfig := GetDefaultCookieConfigs()
	c.SetCookie("Authorization", "", -1, accConfig.Path, accConfig.Domain, accConfig.Secure, accConfig.HttpOnly)
	c.SetCookie("RefreshToken", "", -1, refConfig.Path, refConfig.Domain, refConfig.Secure, refConfig.HttpOnly)
}

func createAccessToken(UserID uint, accExpiresAt time.Time, jwtSecret string) (string, error) {
	accessTokenID := uuid.New().String()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"jti": accessTokenID,
		"exp": accExpiresAt.Unix(),
	})

	return accessToken.SignedString([]byte(jwtSecret))
}

func createRefreshToken(UserID uint, refExpiresAt time.Time, jwtSecret string) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"exp": refExpiresAt.Unix(),
	})

	return refreshToken.SignedString([]byte(jwtSecret))
}

// GenerateAndSetToken generates access and refresh tokens and sets the access token in a cookie
func GenerateAndSetToken(
	c *gin.Context,
	UserID uint,
	jwtSecret string,
) (*TokenMetadata, error) {
	accExp := config.GetEnvAsInt("JWT_EXPIRATION_SECONDS", 900, true)             // Default 15 mins
	refExp := config.GetEnvAsInt("REFRESH_TOKEN_EXPIRATION_SECONDS", 86400, true) // Default 24 hours

	accExpiresAt := time.Now().Add(time.Duration(accExp) * time.Second)
	refExpiresAt := time.Now().Add(time.Duration(refExp) * time.Second)
	fmt.Printf("Token expiration times set: %v seconds for access, %v seconds for refresh\n", accExp, refExp)

	// Create tokens
	accTokenStr, accErr := createAccessToken(UserID, accExpiresAt, jwtSecret)
	refTokenStr, refErr := createRefreshToken(UserID, refExpiresAt, jwtSecret)

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
