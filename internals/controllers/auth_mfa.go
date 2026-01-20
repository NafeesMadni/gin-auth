package controllers

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"

	"gin-auth/internals/models"
	"gin-auth/internals/utils"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

type MFAController struct {
	DB           *gorm.DB
	TokenManager *utils.TokenManager
	// AppName is the name of the application used for TOTP issuer
	AppName       string
	EncryptionKey string
}

func NewMFAController(db *gorm.DB, tokenManager *utils.TokenManager, appName string, encryptionKey string) *MFAController {
	return &MFAController{
		DB:            db,
		TokenManager:  tokenManager,
		AppName:       appName,
		EncryptionKey: encryptionKey,
	}
}

func (m *MFAController) Setup2FA(c *gin.Context) {
	// get user from context (which was set in middleware)
	user, _ := c.Get("user")
	u := user.(models.User)

	// Generate a new TOTP Key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.AppName,
		AccountName: u.Email,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate 2FA key"})
		return
	}

	encrypted_secret, err := utils.Encrypt(key.Secret(), m.EncryptionKey)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to encrypt 2FA secret"})
		return
	}

	// Save the Secret to the user's record
	m.DB.Model(&u).Update("TwoFASecret", encrypted_secret)

	// Generate QR Code as a Base64 image
	img, _ := key.Image(200, 200)
	var buf bytes.Buffer
	png.Encode(&buf, img)
	imgBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	c.JSON(200, gin.H{
		"secret":      key.Secret(),
		"qr_code_url": "data:image/png;base64," + imgBase64,
	})
}

func (m *MFAController) Activate2FA(c *gin.Context) {
	var body struct {
		Code string `json:"code" binding:"required"`
	}
	c.Bind(&body)

	// get user from context (which was set in middleware)
	user, _ := c.Get("user")
	u := user.(models.User)

	decryptedSecret, err := utils.Decrypt(u.TwoFASecret, m.EncryptionKey)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to decrypt 2FA secret"})
		return
	}

	if !utils.Validate2FA(body.Code, decryptedSecret) {
		c.JSON(400, gin.H{"error": "Invalid verification code"})
		return
	}

	m.DB.Model(&u).Update("TwoFAEnabled", true)
	c.JSON(200, gin.H{"message": "2FA activated successfully"})
}

func (m *MFAController) LoginVerify2FA(c *gin.Context) {
	var body struct {
		Email string `json:"email" binding:"required"`
		Code  string `json:"code" binding:"required"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email and Code are required"})
		return
	}

	var user models.User
	if err := m.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	if !user.TwoFAEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2FA is not enabled for this account"})
		return
	}

	// Decrypt the stored TOTP secret
	decryptedSecret, err := utils.Decrypt(user.TwoFASecret, m.EncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process security key"})
		return
	}

	if !utils.Validate2FA(body.Code, decryptedSecret) {
		c.JSON(400, gin.H{"error": "Invalid verification code"})
		return
	}

	// Success! Create the final session and set JWT cookies
	tokenMetadata, err := m.TokenManager.GenerateAndSetToken(c, user.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "You'r verified, logged in successfully.", "access_token": tokenMetadata.AccessToken, "refresh_token": tokenMetadata.RefreshToken})
}
