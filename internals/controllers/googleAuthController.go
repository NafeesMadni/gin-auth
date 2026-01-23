package controllers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"gin-auth/internals/config"
	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// GoogleAuthController handles only Google-specific OAuth logic
type GoogleAuthController struct {
	DB           *gorm.DB
	Config       *oauth2.Config
	TokenManager *utils.TokenManager
}

// NewGoogleAuthController initializes the config once at startup
func NewGoogleAuthController(db *gorm.DB, tokenManager *utils.TokenManager) *GoogleAuthController {
	return &GoogleAuthController{
		DB: db,
		Config: &oauth2.Config{
			ClientID:     config.GetEnv("GOOGLE_CLIENT_ID"),
			ClientSecret: config.GetEnv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  config.GetEnv("GOOGLE_REDIRECT_URL"),
			Endpoint:     google.Endpoint,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		},
		TokenManager: tokenManager,
	}
}

// Login redirects the user to Google's consent page
func (g *GoogleAuthController) Login(c *gin.Context) {
	// In production, generate a random string and save it in a cookie/session
	state := "random-state-string"
	url := g.Config.AuthCodeURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Callback handles the callback from Google
func (g *GoogleAuthController) Callback(c *gin.Context) {
	code := c.Query("code")

	// Use the config to exchange the code for a token
	token, err := g.Config.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Fetch Detailed User Info
	resp, err := g.Config.Client(context.Background(), token).Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user info"})
		return
	}
	defer resp.Body.Close()

	var googleUser struct {
		Sub           string `json:"sub"` // Unique Google ID
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Picture       string `json:"picture"`
		Name          string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user info"})
		return
	}

	if !googleUser.EmailVerified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Google email not verified"})
		return
	}

	// Smart Persistence: Find or Update
	var user models.User
	// Try to find by GoogleID first, then by Email
	result := g.DB.Where("google_id = ? OR email = ?", googleUser.Sub, googleUser.Email).First(&user)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			// Case A: New User
			user = models.User{
				Email:      googleUser.Email,
				GoogleID:   googleUser.Sub,
				IsVerified: true,
				Avatar:     googleUser.Picture,
				FullName:   googleUser.Name,
			}
			if err := g.DB.Create(&user).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
				return
			}
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}
	} else {
		// Case B: User Exists
		// Optional: Update their GoogleID if they previously signed up via password
		// This "links" their existing email account to their Google profile
		if err := g.DB.Model(&user).Updates(map[string]interface{}{
			"google_id": googleUser.Sub,
			"avatar":    googleUser.Picture, // Sync latest profile picture
			"full_name": googleUser.Name,

			// Account Recovery & Linking:
			// If a user previously initiated a standard email signup but did not complete
			// verification, logging in via Google acts as an implicit verification.
			// We synchronize the account state, clear stale OTP data, and promote
			// the user to 'verified' status based on Google's identity authority.
			"is_verified":     true,
			"otp_code":        "",
			"signup_id":       "",
			"code_expires_at": time.Time{},
		}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to link Google account"})
			return
		}
	}

	// Issue Session Tokens
	tokenMetadata, err := g.TokenManager.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token generation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome " + user.Email,
		"tokens":  tokenMetadata,
		"data":    googleUser,
	})
}
