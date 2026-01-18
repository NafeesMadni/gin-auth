package controllers

import (
	"context"
	"encoding/json"
	"gin-auth/internals/initializers"
	"gin-auth/internals/models"
	"gin-auth/internals/utils"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Configure the Google OAuth2 settings
func getGoogleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
	}
}

// Redirects the user to Google's consent page
func GoogleLogin(c *gin.Context) {
	config := getGoogleOAuthConfig()
	// In production, 'state' should be a random string saved in a cookie to prevent CSRF
	url := config.AuthCodeURL("state-token")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// Handles the data returned from Google
func GoogleCallback(c *gin.Context) {
	config := getGoogleOAuthConfig()

	// Exchange the 'code' for a token
	code := c.Query("code")
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Use the token to get User Info from Google
	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get user info"})
		return
	}
	defer response.Body.Close()

	var googleUser struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	}
	json.NewDecoder(response.Body).Decode(&googleUser)

	var user models.User
	initializers.DB.Where("email = ?", googleUser.Email).First(&user)

	if user.ID == 0 {
		user = models.User{Email: googleUser.Email}
		initializers.DB.Create(&user)
	}

	tokenString, err := utils.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged in via Google successfully", "token": tokenString})
}
