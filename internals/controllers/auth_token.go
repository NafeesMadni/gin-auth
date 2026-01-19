package controllers

import (
	"log"
	"net/http"
	"time"

	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type TokenController struct {
	DB        *gorm.DB
	JWTSecret string
}

func NewTokenController(db *gorm.DB, jwtSecret string) *TokenController {
	return &TokenController{DB: db, JWTSecret: jwtSecret}
}

func (t *TokenController) Validate(c *gin.Context) {
	// get user from context (which was set in middleware)
	user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": "You are logged in!",
		"user":    user,
	})
}

func (t *TokenController) RefreshToken(c *gin.Context) {
	refreshTokenStr, err := c.Cookie("RefreshToken")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Find the session in the DB
	var session models.Session
	if err := t.DB.Where("refresh_token = ?", refreshTokenStr).First(&session).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found or revoked"})
		return
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		t.DB.Unscoped().Delete(&session) // Clean up expired session
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		return
	}

	// ROTATION: Delete the old session and create a new one
	t.DB.Unscoped().Delete(&session)

	tokens, err := utils.GenerateAndSetToken(c, session.UserID, t.JWTSecret)
	if err != nil {
		log.Printf("Rotation Failure for User %d: %v", session.UserID, err)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Session rotation failed. Please log in again.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed", "access_token": tokens.AccessToken})
}
