package controllers

import (
	"context"
	"encoding/json"
	"net/http"

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

	// Fetch user info
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user info"})
		return
	}
	defer response.Body.Close()

	var googleUser struct {
		Email string `json:"email"`
	}
	json.NewDecoder(response.Body).Decode(&googleUser)

	// User persistence logic
	var user models.User
	g.DB.Where("email = ?", googleUser.Email).First(&user)

	if user.ID == 0 {
		user = models.User{Email: googleUser.Email, IsVerified: true}
		g.DB.Create(&user)
	}

	tokenMetadata, err := g.TokenManager.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in via Google successfully", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
}
