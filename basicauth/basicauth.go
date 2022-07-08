package basicauth

import (
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type GetPasswordFunc func(username string) (password string, exists bool)

type BasicAuth struct {
	GetPassword GetPasswordFunc // Function which returns a salted and hashed password for a given username
	Realm       string          // Realm to send to the user
	Salt        string          // String used to salt the passwords
	Hash        crypto.Hash     // Hash function to hash the salted password
}

func (ba *BasicAuth) CreateMiddleware() func(c *gin.Context) {
	// Figure out username
	realmString := `Basic realm="Authorization Required"`
	if ba.Realm != "" {
		realmString = fmt.Sprintf(`Basic realm="%v"`, ba.Realm)
	}

	return func(c *gin.Context) {
		// Parse username and password from authorization header
		username, password, valid := parseAuthorizationHeader(c.Request.Header.Get("Authorization"))
		if !valid {
			c.Header("WWW-Authenticate", realmString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Get real hashed and salted password from store
		expectedPassword, exists := ba.GetPassword(username)
		if !exists {
			c.Header("WWW-Authenticate", realmString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// Hash and salt the password
		hashedPassword := ba.HashPassword(password)

		fmt.Printf("expectedPassword: %v\nhashedPassword:   %v\n", expectedPassword, hashedPassword)

		if subtle.ConstantTimeCompare([]byte(hashedPassword), []byte(expectedPassword)) == 0 {
			c.Header("WWW-Authenticate", realmString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}

func (ba *BasicAuth) HashPassword(password string) string {
	saltedPassword := fmt.Sprintf("%v.%v", password, ba.Salt)
	return hashString(saltedPassword, ba.Hash)
}

// Util
func hashString(s string, hash crypto.Hash) string {
	h := hash.New()
	h.Write([]byte(s)) // cannot return an error according to hash documentation
	return fmt.Sprintf(`%x`, h.Sum(nil))
}

func parseAuthorizationHeader(header string) (username string, password string, valid bool) {
	authType, authValue, found := strings.Cut(header, " ")
	if !found || authType != "Basic" {
		return
	}

	usernamePasswordPair, err := base64.StdEncoding.DecodeString(authValue)
	if err != nil {
		return
	}

	username, password, valid = strings.Cut(string(usernamePasswordPair), ":")
	return
}
