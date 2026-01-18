package utils

// CookieConfig groups settings for cleaner function signatures
type CookieConfig struct {
	Path     string `default:""`      // Path: e.g., "/", "/auth/refresh"
	Domain   string `default:""`      // Domain: Set to your domain, e.g., "example.com"
	Secure   bool   `default:"false"` // Secure: Set to true if using HTTPS
	HttpOnly bool   `default:"true"`  // HttpOnly: CRITICAL for XSS protection
}

// TokenMetadata holds the results of token generation
type TokenMetadata struct {
	AccessToken  string
	RefreshToken string
}
