package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

func SendVerificationEmail(toEmail string, code string) error {
	from := os.Getenv("GMAIL_USER")
	password := os.Getenv("GMAIL_APP_PASSWORD")
	brandName := os.Getenv("APP_NAME")
	expiration := os.Getenv("VERIFICATION_EXPIRATION_MINUTES")

	// SMTP server configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"

	subject := fmt.Sprintf("Subject: %s - Verify Your Email Address\n", brandName)
	mime := "MIME-version: 1.0;\nContent-Type: text/plain; charset=\"UTF-8\";\n\n"

	body := fmt.Sprintf(
		"Hello,\n\n"+
			"Thank you for signing up for %s! To complete your registration, please use the verification code below:\n\n"+
			"Verification Code: %s\n\n"+
			"This code will expire in %s minutes. If you did not request this email, please ignore it.\n\n"+
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
