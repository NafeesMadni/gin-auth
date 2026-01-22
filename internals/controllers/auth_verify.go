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
	DB           *gorm.DB
	EmailManager *utils.EmailManager
	TokenManager *utils.TokenManager
}

type VerifyReqBody struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

type ResendReqBody struct {
	Email string `json:"email" binding:"required,email"`
}

func NewVerificationController(db *gorm.DB, emailManager *utils.EmailManager, tokenManager *utils.TokenManager) *VerificationController {
	return &VerificationController{
		DB:           db,
		EmailManager: emailManager,
		TokenManager: tokenManager,
	}
}

func (v *VerificationController) VerifySignup(c *gin.Context) {
	cookieID, err := c.Cookie("Signup-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please sign up again."})
		return
	}

	var body VerifyReqBody

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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

	if user.OTPCode != body.Code {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	// Mark as verified
	v.DB.Model(&user).Updates(map[string]interface{}{
		"IsVerified":    true,
		"OTPCode":       "",          // Clear the code after use
		"CodeExpiresAt": time.Time{}, // Clear the expiration time
	})

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func (v *VerificationController) VerifyLogin(c *gin.Context) {
	cookieID, err := c.Cookie("Login-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please login again."})
		return
	}

	var body VerifyReqBody

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var lc models.LoginChallenge
	if err := v.DB.Where("email = ? AND challenge_id = ?", body.Email, cookieID).First(&lc).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification session."})
		return
	}

	if time.Now().After(lc.SessionExpireAt) {
		v.DB.Unscoped().Delete(&lc)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session expired, please login again."})
		return
	}

	if time.Now().After(lc.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code expired, please resend code."})
		return
	}

	if lc.OTPCode != body.Code {
		newAttempts := lc.Attempts - 1
		if newAttempts <= 0 {
			v.DB.Unscoped().Delete(&lc)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Too many failed attempts. Session cleared."})
			return
		}

		v.DB.Model(&lc).Update("attempts", newAttempts)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code", "attempts_left": newAttempts})
		return
	}

	tokenMetadata, err := v.TokenManager.GenerateAndSetToken(c, lc.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Delete the challenge after a successful login so it can't be reused
	v.DB.Unscoped().Delete(&lc)

	c.JSON(http.StatusOK, gin.H{
		"message":       "Logged in successfully.",
		"access_token":  tokenMetadata.AccessToken,
		"refresh_token": tokenMetadata.RefreshToken,
	})
}

// ResendSignupOTP handles requests to resend the verification code to the user's email for signups confirmation.
func (v *VerificationController) ResendSignupOTP(c *gin.Context) {
	cookieID, err := c.Cookie("Signup-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please sign up again."})
		return
	}

	var body ResendReqBody

	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	var user models.User
	if err := v.DB.Where("email = ? AND signup_id = ?", body.Email, cookieID).First(&user).Error; err != nil {
		// Security: Use a generic success message to prevent account enumeration
		// This way, attackers cannot determine if an email is registered or not
		c.JSON(http.StatusOK, gin.H{"message": "If the session is valid, a new code has been sent."})
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

	newCode := v.EmailManager.GenerateVerificationCode()

	if err := v.DB.Model(&user).Updates(map[string]interface{}{
		"otp_code":        newCode,
		"code_expires_at": time.Now().Add(time.Duration(v.EmailManager.Config.CodeExp) * time.Minute),
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh code"})
		return
	}

	go v.EmailManager.SendSignupOTP(user.Email, newCode)

	c.JSON(http.StatusOK, gin.H{"message": "A new verification code has been sent to your email"})
}

// ResendLoginOTP handles requests to resend the verification code to the user's email for login confirmation.
func (v *VerificationController) ResendLoginOTP(c *gin.Context) {
	cookieID, err := c.Cookie("Login-Session")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired. Please login again."})
		return
	}

	var body ResendReqBody

	if c.ShouldBindJSON(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email address"})
		return
	}

	var lc models.LoginChallenge
	if err := v.DB.Where("email = ? AND challenge_id = ?", body.Email, cookieID).First(&lc).Error; err != nil {
		// Security: Use a generic success message to prevent account enumeration
		// This way, attackers cannot determine if an email is registered or not
		c.JSON(http.StatusOK, gin.H{"message": "If the session is valid, a new code has been sent."})
		return
	}

	if time.Now().After(lc.SessionExpireAt) {
		v.DB.Unscoped().Delete(&lc)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session expired, please login again."})
		return
	}

	// --- COOLDOWN LOGIC ---
	// Check if the last code was sent less than 1 minute ago
	if time.Now().Before(lc.UpdatedAt.Add(1 * time.Minute)) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Please wait a minute before requesting a new code"})
		return
	}

	newCode := v.EmailManager.GenerateVerificationCode()

	if err := v.DB.Model(&lc).Updates(map[string]interface{}{
		"otp_code":        newCode,
		"attempts":        3,
		"code_expires_at": time.Now().Add(time.Duration(v.EmailManager.Config.CodeExp) * time.Minute),
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh code"})
		return
	}

	go v.EmailManager.SendLoginOTP(lc.Email, newCode)

	c.JSON(http.StatusOK, gin.H{"message": "A new verification code has been sent to your email"})
}
