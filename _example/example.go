package main

import (
	"crypto"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	auth "github.com/wadu436/gin-auth"
)

var accounts map[string]auth.User = make(map[string]auth.User)

func main() {
	r := gin.Default()

	// Create framework
	a := auth.Auth{
		LoadUser: func(username string) (user auth.User, exists bool) {
			user, exists = accounts[username]
			return
		},
		StoreUser: func(user auth.User) {
			accounts[user.Username] = user
		},
		Hash:       crypto.SHA512,
		SaltLength: 32,
	}

	// Add user to the backing store
	a.UpdateUser("foo", "bar")

	// Public route
	r.GET("/public", func(c *gin.Context) {
		c.String(http.StatusOK, "boring public stuff")
	})

	// Authenticated routes
	auth := r.Group("/auth", a.BasicAuthMiddleware)
	auth.GET("/secret", func(c *gin.Context) {
		c.String(http.StatusOK, "exciting super secret stuff!")
	})

	err := r.Run(":8080")
	log.Fatal(err)
}
