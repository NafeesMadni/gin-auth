package middleware

import (
	"gin-auth/internals/initializers"
	"gin-auth/internals/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	tokenString, err := c.Cookie("Authorization")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		jti := claims["jti"].(string)

		// Check if this JTI exists in the Blacklist table
		var blacklisted models.Blacklist
		initializers.DB.Where("jti = ?", jti).First(&blacklisted)

		if blacklisted.ID != 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid (logged out)"})
			return
		}

		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var user models.User
		initializers.DB.First(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("user", user)
		c.Next() // continue to the next handler

	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
