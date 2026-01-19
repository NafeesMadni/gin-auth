package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/smtp"
	"strconv"
)

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	AppName  string
	CodeExp  int
}

// GenerateVerificationCode uses crypto/rand for better security
func GenerateVerificationCode() string {
	max := big.NewInt(1000000)
	n, _ := rand.Int(rand.Reader, max)
	return fmt.Sprintf("%06d", n.Int64())
}

func SendVerificationEmail(toEmail string, code string, smtp_config *SMTPConfig) error {
	from := smtp_config.User
	password := smtp_config.Password
	brandName := smtp_config.AppName
	expiration := smtp_config.CodeExp

	// SMTP server configuration
	smtpHost := smtp_config.Host
	smtpPort := strconv.Itoa(smtp_config.Port)

	subject := fmt.Sprintf("Subject: %s - Verify Your Email Address\n", brandName)
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"

	body := fmt.Sprintf(
		"Hello,\n\n"+
			"Thank you for signing up for %s! To complete your registration, please use the verification code below:\n\n"+
			"Verification Code: %s\n\n"+
			"This code will expire in %d minutes. If you did not request this email, please ignore it.\n\n"+
			"Best regards,\n"+
			"The %s Team",
		brandName, code, expiration, brandName)

	// Combine headers and body
	message := []byte(subject + mime + body)

	// Authentication
	auth := smtp.PlainAuth("", from, password, smtpHost)

	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{toEmail}, message)
	return err
}
