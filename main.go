package main

import (
	"crypto"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wadu436/gin-basic-auth/basicauth"
)

func main() {
	r := gin.Default()

	ba := basicauth.BasicAuth{
		GetPassword: func(username string) (string, bool) {
			if username == "admin" {
				return "0083e503236b5e09ea6d4dc95760914b", true //MD5 hashed admin.secret
			} else if username == "test" {
				return "25bf25518718a0b5ba8411087dac9ccd", true //MD5 hashed test.secret
			} else {
				return "", false
			}
		},
		Hash: crypto.MD5,
		Salt: "secret",
	}

	r.GET("/", ba.CreateMiddleware(), func(c *gin.Context) {
		c.String(http.StatusOK, "Hello World!")
	})

	r.Run(":8080")
}
