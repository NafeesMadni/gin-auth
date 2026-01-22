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

func NewVerificationController(db *gorm.DB, emailManager *utils.EmailManager, tokenManager *utils.TokenManager) *VerificationController {
	return &VerificationController{
		DB:           db,
		EmailManager: emailManager,
		TokenManager: tokenManager,
	}
}

type VerifyReqBody struct {
	Email string `json:"email" binding:"required,email"`
	Code  string `json:"code" binding:"required"`
}

type ResendReqBody struct {
	Email string `json:"email" binding:"required,email"`
}

// Internal error helper to reduce boilerplate
func (v *VerificationController) abortWithClear(c *gin.Context, status int, msg map[string]any, isSignup bool) {
	if isSignup {
		v.TokenManager.ClearSignupSession(c)
	} else {
		v.TokenManager.ClearLoginSession(c)
	}
	c.AbortWithStatusJSON(status, msg)
}

func (v *VerificationController) VerifySignup(c *gin.Context) {
	cookieID, err := c.Cookie(v.TokenManager.Signup.Name) // Dynamic name from TokenManager
	if err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Session expired. Please sign up again."}, true)
		return
	}

	var body VerifyReqBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var user models.User
	if err := v.DB.Where("email = ? AND signup_id = ?", body.Email, cookieID).First(&user).Error; err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Invalid verification session."}, true)
		return
	}

	if user.IsVerified {
		v.abortWithClear(c, http.StatusBadRequest, map[string]any{"error": "Email already verified"}, true)
		return
	}

	if time.Now().After(user.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code expired"})
		return
	}

	// Use your internal validation logic
	if user.OTPCode != body.Code {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code"})
		return
	}

	v.DB.Model(&user).Updates(map[string]interface{}{
		"is_verified":     true,
		"otp_code":        "",
		"signup_id":       "",
		"code_expires_at": time.Time{},
	})

	v.TokenManager.ClearSignupSession(c)
	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully"})
}

func (v *VerificationController) VerifyLogin(c *gin.Context) {
	cookieID, err := c.Cookie(v.TokenManager.Login.Name)
	if err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Session expired. Please login again."}, false)
		return
	}

	var body VerifyReqBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	var lc models.LoginChallenge
	if err := v.DB.Where("email = ? AND challenge_id = ?", body.Email, cookieID).First(&lc).Error; err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Invalid verification session"}, false)
		return
	}

	if time.Now().After(lc.SessionExpireAt) {
		v.DB.Unscoped().Delete(&lc)
		v.abortWithClear(c, http.StatusBadRequest, map[string]any{"error": "Session expired, please login again."}, false)
		return
	}

	if time.Now().After(lc.CodeExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code expired, please resend code."})
		return
	}

	if lc.OTPCode != body.Code {
		newAttempts := lc.Attempts - 1
		if newAttempts <= 0 {
			// Treat this as a threat - Delete the LoginChallenge  & Clear the Login Session
			v.DB.Unscoped().Delete(&lc)
			v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Too many failed attempts. Session cleared."}, false)
			return
		}
		v.DB.Model(&lc).Update("attempts", newAttempts)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid code", "attempts_left": newAttempts})
		return
	}

	// Standard Token Generation
	tokenMetadata, err := v.TokenManager.GenerateAndSetToken(c, lc.UserID)
	if err != nil {
		v.abortWithClear(c, http.StatusInternalServerError, map[string]any{"error": "Failed to generate tokens"}, false)
		return
	}

	v.DB.Unscoped().Delete(&lc)
	v.TokenManager.ClearLoginSession(c)

	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully", "data": tokenMetadata})
}

// ResendSignupOTP handles requests to resend the verification code to the user's email for signups confirmation.
func (v *VerificationController) ResendSignupOTP(c *gin.Context) {
	cookieID, err := c.Cookie(v.TokenManager.Signup.Name)
	if err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Session expired. Please sign up again."}, true)
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
		v.abortWithClear(c, http.StatusOK, map[string]any{"message": "If the session is valid, a new code has been sent."}, true)
		return
	}

	if user.IsVerified {
		v.abortWithClear(c, http.StatusBadRequest, map[string]any{"error": "Account is already verified."}, true)
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
	cookieID, err := c.Cookie(v.TokenManager.Login.Name)
	if err != nil {
		v.abortWithClear(c, http.StatusUnauthorized, map[string]any{"error": "Session expired. Please login again."}, false)
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
		v.abortWithClear(c, http.StatusOK, map[string]any{"message": "If the session is valid, a new code has been sent."}, false)
		return
	}

	if time.Now().After(lc.SessionExpireAt) {
		v.DB.Unscoped().Delete(&lc)
		v.TokenManager.ClearLoginSession(c)

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
