package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/smtp"
	"strings"
)

type SMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	AppName  string
	CodeExp  int
}

type EmailManager struct {
	Config *SMTPConfig
}

func NewEmailManager(config *SMTPConfig) *EmailManager {
	return &EmailManager{
		Config: config,
	}
}

// GenerateVerificationCode uses crypto/rand for better security
func (em *EmailManager) GenerateVerificationCode() string {
	max := big.NewInt(1000000)
	n, _ := rand.Int(rand.Reader, max)
	return fmt.Sprintf("%06d", n.Int64())
}

// send is a private helper that handles the actual SMTP handshake and delivery
func (em *EmailManager) send(toEmail string, subject string, body string) error {
	smtpAddr := fmt.Sprintf("%s:%d", em.Config.Host, em.Config.Port)

	// Constructing headers according to RFC 822 standards
	// Note the use of \r\n (Carriage Return + Line Feed)
	headers := []string{
		fmt.Sprintf("From: %s", em.Config.User),
		fmt.Sprintf("To: %s", toEmail),
		fmt.Sprintf("Subject: %s", subject),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=\"UTF-8\"",
		"", // This empty string creates the necessary blank line between headers and body
		body,
	}

	message := strings.Join(headers, "\r\n")

	auth := smtp.PlainAuth("", em.Config.User, em.Config.Password, em.Config.Host)

	return smtp.SendMail(smtpAddr, auth, em.Config.User, []string{toEmail}, []byte(message))
}

// SendSignupOTP sends a verification email for signup with the given code
func (em *EmailManager) SendSignupOTP(toEmail string, code string) error {
	// We only provide the "clean" subject; the helper will add "Subject: " prefix and CRLF
	subject := fmt.Sprintf("%s - Your Signup Verification Code", em.Config.AppName)

	body := fmt.Sprintf(
		"Hello,\n\n"+
			"Thank you for signing up for %s! To complete your registration, please use the verification code below:\n\n"+
			"Verification Code: %s\n\n"+
			"This code will expire in %d minutes.\n\n"+
			"Best regards,\nThe %s Team",
		em.Config.AppName, code, em.Config.CodeExp, em.Config.AppName)

	return em.send(toEmail, subject, body)
}

// SendLoginOTP sends a verification code for existing user login
func (em *EmailManager) SendLoginOTP(toEmail string, code string) error {
	subject := fmt.Sprintf("%s - Your Login Verification Code", em.Config.AppName)

	body := fmt.Sprintf(
		"Hello,\n\n"+
			"You requested a code to log in to %s. Please use the verification code below to gain access:\n\n"+
			"Login Code: %s\n\n"+
			"This code will expire in %d minutes. If you did not request this login, we recommend updating your security settings.\n\n"+
			"Best regards,\n"+
			"The %s Team",
		em.Config.AppName, code, em.Config.CodeExp, em.Config.AppName)

	return em.send(toEmail, subject, body)
}
