package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const REALM_STRING string = `Basic realm="Authorization Required"`

type LoadUserFunc func(username string) (user User, exists bool)
type StoreUserFunc func(user User)

type User struct {
	Username string
	Password string // hex string of salted hash of the password
	Salt     string
}

type Auth struct {
	LoadUser   LoadUserFunc  // Returns a user from the backing store
	StoreUser  StoreUserFunc // Stores a user to the backing store
	Hash       crypto.Hash   // Hash function to hash the salted password. Use at least SHA-2 (such as SHA-256, SHA-512, etc)
	SaltLength uint          // Length of the generated salts. The generated salt should be at least the same length as the length of the output of the hash function. For example, it should be at least 256/8 = 32 for SHA-256
}

// Salts and hashes the password, then calls StoreUser to write the new or updated user to the backing store
func (a *Auth) UpdateUser(username string, password string) {
	salt := generateSalt(a.SaltLength)
	hashedPassword := a.hashAndSaltPassword(password, salt)
	user := User{Username: username, Password: hashedPassword, Salt: salt}
	a.StoreUser(user)
}

// Middleware function for gin
func (a *Auth) BasicAuthMiddleware(c *gin.Context) {
	// Parse username and password from authorization header
	username, password, valid := parseAuthorizationHeader(c.Request.Header.Get("Authorization"))
	if !valid || username == "" {
		c.Header("WWW-Authenticate", REALM_STRING)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Load relevant user from backing store, salt and hash the received password and compare
	user, _ := a.LoadUser(username)
	hashedPassword := a.hashAndSaltPassword(password, user.Salt)
	if subtle.ConstantTimeCompare([]byte(hashedPassword), []byte(user.Password)) == 0 {
		c.Header("WWW-Authenticate", REALM_STRING)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

// Utility stuff
func (a *Auth) hashString(s string) string {
	h := a.Hash.New()
	h.Write([]byte(s)) // cannot return an error according to hash documentation
	return fmt.Sprintf("%x", h.Sum(nil))
}

func (a *Auth) hashAndSaltPassword(password string, salt string) string {
	return a.hashString(password + salt)
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

// Salt stuff
var chars []byte = []byte(`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&`)
var bigInt = big.NewInt(int64(len(chars)))

func generateSalt(n uint) string {
	var salt []byte = make([]byte, n)
	for j := range salt {
		i, _ := rand.Int(rand.Reader, bigInt)
		salt[j] = chars[i.Int64()]
	}
	return string(salt)
}
