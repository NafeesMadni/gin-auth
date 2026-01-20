package config

// CookieConfig defines the shared security baseline for all cookies issued by the server
type CookieConfig struct {
	// Domain for the cookies
	Domain string
	// isSecure indicates if cookies should be marked as Secure
	IsSecure bool
	// HttpOnly indicates if cookies should be marked as HttpOnly for security
	HttpOnly bool
}
