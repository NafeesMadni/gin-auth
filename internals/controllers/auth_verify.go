package controllers

import (
	"net/http"
	"time"

	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type VerificationController struct {
	DB     *gorm.DB
	Config *utils.SMTPConfig
}

func NewVerificationController(db *gorm.DB, smtp_config *utils.SMTPConfig) *VerificationController {
	return &VerificationController{
		DB:     db,
		Config: smtp_config,
	}
}

func (v *VerificationController) VerifyEmail(c *gin.Context) {
	cookieID, err := c.Cookie("Signup-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please sign up again."})
		return
	}

	var body struct {
		Email string `json:"email" binding:"required,email`
		Code  string `json:"code"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	var user models.User
	if err := v.DB.Where("email = ? AND signup_id = ?", body.Email, cookieID).First(&user).Error; err != nil {
		// If the hacker initiated the last signup, the cookie won't match the DB
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification session. Please sign up again."})
		return
	}

	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email already verified"})
		return
	}

	// Check if expired
	if time.Now().After(user.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code expired"})
		return
	}

	if user.VerificationCode != body.Code {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// Mark as verified
	v.DB.Model(&user).Updates(map[string]interface{}{
		"IsVerified":       true,
		"VerificationCode": "",          // Clear the code after use
		"CodeExpiresAt":    time.Time{}, // Clear the expiration time
	})

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

// ResendVerificationCode handles requests to resend the verification code to the user's email for signups confirmation.
func (v *VerificationController) ResendVerificationCode(c *gin.Context) {
	cookieID, err := c.Cookie("Signup-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please sign up again."})
		return
	}

	var body struct {
		Email string `json:"email" binding:"required,email"`
	}

	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	var user models.User
	if err := v.DB.Where("email = ? AND signup_id = ?", body.Email, cookieID).First(&user).Error; err != nil {
		// Security: Use a generic success message to prevent account enumeration
		// This way, attackers cannot determine if an email is registered or not
		c.JSON(http.StatusOK, gin.H{"error": "If the session is valid, a new code has been sent."})
		return
	}

	if user.IsVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Account is already verified"})
		return
	}

	// --- COOLDOWN LOGIC ---
	// Check if the last code was sent less than 1 minute ago
	if time.Now().Before(user.UpdatedAt.Add(1 * time.Minute)) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Please wait a minute before requesting a new code"})
		return
	}

	newCode := utils.GenerateVerificationCode()

	v.DB.Model(&user).Updates(models.User{
		VerificationCode: newCode,
		CodeExpiresAt:    time.Now().Add(time.Duration(v.Config.CodeExp) * time.Minute),
	})

	go utils.SendVerificationEmail(user.Email, newCode, v.Config)

	c.JSON(http.StatusOK, gin.H{"message": "A new verification code has been sent to your email"})
}
