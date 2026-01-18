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

func createRefreshToken(UserID uint, refExp int) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"exp": time.Now().Add(time.Duration(refExp) * time.Second).Unix(),
	})

	return refreshToken.SignedString([]byte(os.Getenv("SECRET")))
}

func createAccessToken(UserID uint, accExp int) (string, error) {
	accessTokenID := uuid.New().String()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": UserID,
		"jti": accessTokenID,
		"exp": time.Now().Add(time.Duration(accExp) * time.Second).Unix(),
	})

	return accessToken.SignedString([]byte(os.Getenv("SECRET")))
}

// GenerateAndSetToken generates access and refresh tokens and sets the access token in a cookie
func GenerateAndSetToken(
	c *gin.Context,
	UserID uint,
	accCookieConfig CookieConfig,
	refCookieConfig CookieConfig,
) (*TokenMetadata, error) {

	accExp, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_SECONDS"))
	refExp, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION_SECONDS"))

	accTokenStr, err := createAccessToken(UserID, accExp)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create access token"})
		return nil, err
	}

	refTokenStr, err := createRefreshToken(UserID, refExp)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create refresh token"})
		return nil, err
	}

	c.SetSameSite(http.SameSiteLaxMode)

	c.SetCookie(
		"Authorization",
		accTokenStr,
		accExp,
		accCookieConfig.Path,
		accCookieConfig.Domain,
		accCookieConfig.Secure,
		accCookieConfig.HttpOnly,
	)

	c.SetCookie(
		"RefreshToken",
		refTokenStr,
		refExp,
		refCookieConfig.Path,
		refCookieConfig.Domain,
		refCookieConfig.Secure,
		refCookieConfig.HttpOnly,
	)

	return &TokenMetadata{AccessToken: accTokenStr, RefreshToken: refTokenStr}, nil
}
