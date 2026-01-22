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

// TokenMetadata holds the results of token generation

type TokenMetadata struct {
	AccessToken  string
	RefreshToken string
}

type CookieSetting struct {
	Name   string
	Path   string
	MaxAge int
}

type TokenManager struct {
	DB           *gorm.DB
	CookieConfig *config.CookieConfig
	JWTSecret    string
	// Config groups
	Access  CookieSetting
	Refresh CookieSetting
	Signup  CookieSetting
	Login   CookieSetting
}

func NewTokenManager(db *gorm.DB, cfg *config.CookieConfig, secret string, access, refresh, signup, login CookieSetting) *TokenManager {
	return &TokenManager{
		DB:           db,
		CookieConfig: cfg,
		JWTSecret:    secret,
		Access:       access,
		Refresh:      refresh,
		Signup:       signup,
		Login:        login,
	}
}

// --- Internal Helpers ---
func (tm *TokenManager) setCookie(c *gin.Context, settings CookieSetting, value string) {
	// Set SameSite for ALL cookies to prevent CSRF
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		settings.Name,
		value,
		settings.MaxAge,
		settings.Path,
		tm.CookieConfig.Domain,
		tm.CookieConfig.IsSecure,
		tm.CookieConfig.HttpOnly,
	)
}

func (tm *TokenManager) clearCookie(c *gin.Context, settings CookieSetting) {
	c.SetCookie(
		settings.Name, "", -1, settings.Path, tm.CookieConfig.Domain, tm.CookieConfig.IsSecure, tm.CookieConfig.HttpOnly,
	)
}

func (tm *TokenManager) generateJWT(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(tm.JWTSecret))
}

// --- Public Methods ---

func (tm *TokenManager) SetSignupSession(c *gin.Context, id string) { tm.setCookie(c, tm.Signup, id) }
func (tm *TokenManager) ClearSignupSession(c *gin.Context)          { tm.clearCookie(c, tm.Signup) }

func (tm *TokenManager) SetLoginSession(c *gin.Context, id string) { tm.setCookie(c, tm.Login, id) }
func (tm *TokenManager) ClearLoginSession(c *gin.Context)          { tm.clearCookie(c, tm.Login) }

func (tm *TokenManager) SetJWTCookies(c *gin.Context, acc, ref string) {
	tm.setCookie(c, tm.Access, acc)
	tm.setCookie(c, tm.Refresh, ref)
}

func (tm *TokenManager) ClearJWTCookies(c *gin.Context) {
	tm.clearCookie(c, tm.Access)
	tm.clearCookie(c, tm.Refresh)
}

// GenerateAndSetToken generates access and refresh tokens, stores the refresh token in the database, and sets both tokens in secure cookies
func (tm *TokenManager) GenerateAndSetToken(c *gin.Context, UserID uint) (*TokenMetadata, error) {
	// Calculate expiration times
	accExpiresAt := time.Now().Add(time.Duration(tm.Access.MaxAge) * time.Second)
	refExpiresAt := time.Now().Add(time.Duration(tm.Refresh.MaxAge) * time.Second)
	fmt.Printf("Token expiration times set: %v seconds for access, %v seconds for refresh\n", tm.Access.MaxAge, tm.Refresh.MaxAge)

	// Create tokens
	accTokenStr, err := tm.generateJWT(jwt.MapClaims{"sub": UserID, "jti": uuid.New().String(), "exp": accExpiresAt.Unix()})
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	refTokenStr, err := tm.generateJWT(jwt.MapClaims{"sub": UserID, "exp": refExpiresAt.Unix()})
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	session := models.Session{
		UserID:       UserID,
		RefreshToken: refTokenStr,
		UserAgent:    c.Request.UserAgent(),
		IPAddress:    c.ClientIP(),
		ExpiresAt:    refExpiresAt,
	}

	if err := tm.DB.Create(&session).Error; err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	// Set secure cookies
	tm.SetJWTCookies(c, accTokenStr, refTokenStr)

	return &TokenMetadata{
		AccessToken:  accTokenStr,
		RefreshToken: refTokenStr,
	}, nil
}
