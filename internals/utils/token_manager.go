package utils

import (
	"fmt"
	"net/http"
	"time"

	"gin-auth/internals/config"
	"gin-auth/internals/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TokenManager handles token generation, storage, and cookie management
type TokenManager struct {
	// DB is the database connection used for storing sessions
	DB *gorm.DB
	// CookieConfig holds the shared security baseline for all cookies issued by the server
	CookieConfig *config.CookieConfig
	// JWTSecret is the secret key used for signing tokens (Access and Refresh)
	JWTSecret string
	// AccMaxAge is the expiration time in seconds for Access tokens
	AccMaxAge int
	// RefMaxAge is the expiration time in seconds for Refresh tokens
	RefMaxAge int
	// AccPath for the Access token
	AccPath string
	// RefPath for the Refresh token
	RefPath string
}

// NewTokenManager initializes and returns a new TokenManager instance
func NewTokenManager(db *gorm.DB, cookieConfig *config.CookieConfig, jwtSecret string, accMaxAge int, refMaxAge int, accPath string, refPath string) *TokenManager {
	return &TokenManager{
		DB:           db,
		CookieConfig: cookieConfig,
		JWTSecret:    jwtSecret,
		AccMaxAge:    accMaxAge,
		RefMaxAge:    refMaxAge,
		AccPath:      accPath,
		RefPath:      refPath,
	}
}

// TokenMetadata holds the results of token generation
type TokenMetadata struct {
	AccessToken  string
	RefreshToken string
}

// SetClearCookies clears the Authorization and RefreshToken cookies from the client when he request for logout or refresh token rotation with invalid tokens
func (tm *TokenManager) SetClearCookies(c *gin.Context) {
	c.SetCookie("Authorization", "", -1, tm.AccPath, tm.CookieConfig.Domain, tm.CookieConfig.IsSecure, tm.CookieConfig.HttpOnly)
	c.SetCookie("RefreshToken", "", -1, tm.RefPath, tm.CookieConfig.Domain, tm.CookieConfig.IsSecure, tm.CookieConfig.HttpOnly)
}

// createAccessToken creates a signed JWT access token
func (tm *TokenManager) createAccessToken(UserID uint, expAt time.Time) (string, error) {
	accessTokenID := uuid.New().String()

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"jti": accessTokenID,
		"exp": expAt.Unix(),
	})

	return accessToken.SignedString([]byte(tm.JWTSecret))
}

// createRefreshToken creates a signed JWT refresh token
func (tm *TokenManager) createRefreshToken(UserID uint, expAt time.Time) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"exp": expAt.Unix(),
	})

	return refreshToken.SignedString([]byte(tm.JWTSecret))
}

// GenerateAndSetToken generates access and refresh tokens, stores the refresh token in the database, and sets both tokens in secure cookies
func (tm *TokenManager) GenerateAndSetToken(c *gin.Context, UserID uint) (*TokenMetadata, error) {
	// Calculate expiration times
	accExpiresAt := time.Now().Add(time.Duration(tm.AccMaxAge) * time.Second)
	refExpiresAt := time.Now().Add(time.Duration(tm.RefMaxAge) * time.Second)
	fmt.Printf("Token expiration times set: %v seconds for access, %v seconds for refresh\n", tm.AccMaxAge, tm.RefMaxAge)

	// Create tokens
	accTokenStr, accErr := tm.createAccessToken(UserID, accExpiresAt)
	refTokenStr, refErr := tm.createRefreshToken(UserID, refExpiresAt)

	if accErr != nil {
		tm.SetClearCookies(c)
		return nil, fmt.Errorf("Access token generation failed")
	}
	if refErr != nil {
		tm.SetClearCookies(c)
		return nil, fmt.Errorf("Refresh token generation failed")
	}

	session := models.Session{
		UserID:       UserID,
		RefreshToken: refTokenStr,
		UserAgent:    c.Request.UserAgent(),
		IPAddress:    c.ClientIP(),
		ExpiresAt:    refExpiresAt,
	}

	if err := tm.DB.Create(&session).Error; err != nil {
		// CLEANUP: If DB fails, we must not leave the user with "half-valid" state
		tm.SetClearCookies(c)
		return nil, err
	}

	// Set secure cookies
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", accTokenStr, tm.AccMaxAge, tm.AccPath, tm.CookieConfig.Domain, tm.CookieConfig.IsSecure, tm.CookieConfig.HttpOnly)
	c.SetCookie("RefreshToken", refTokenStr, tm.RefMaxAge, tm.RefPath, tm.CookieConfig.Domain, tm.CookieConfig.IsSecure, tm.CookieConfig.HttpOnly)

	return &TokenMetadata{AccessToken: accTokenStr, RefreshToken: refTokenStr}, nil
}
