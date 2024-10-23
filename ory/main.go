package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	clientID     = "64ee7e3d-0b6e-48d1-bdc0-41fee0f45174"
	clientSecret = "J.WLR-k-EPyyhvjqoJ_8F1HnH7"
	providerURL  = "https://epic-babbage-qcpmjietvo.projects.oryapis.com"
)

func main() {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		log.Fatal(err)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	router := gin.Default()

	router.GET("/login", func(c *gin.Context) {
		state, err := generateRandomState()
		if err != nil {
			c.String(http.StatusInternalServerError, "Error generating state")
			return
		}
		c.SetCookie("state", state, 10, "/", "localhost", false, true)
		url := oauth2Config.AuthCodeURL(state)
		c.Redirect(http.StatusFound, url)
	})

	router.GET("/callback", func(c *gin.Context) {
		state, err := c.Cookie("state")
		if err != nil {
			c.String(http.StatusBadRequest, "Missing state cookie")
			return
		}
		c.SetCookie("state", "", -1, "/", "localhost", false, true)

		if c.Query("state") != state {
			c.String(http.StatusBadRequest, "Invalid state")
			return
		}

		// Create a custom HTTP client for client_secret_post
		client := &http.Client{}
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

		token, err := oauth2Config.Exchange(ctx, c.Query("code"))
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			c.String(http.StatusInternalServerError, "No id_token field in oauth2 token.")
			return
		}

		c.SetCookie("id_token", rawIDToken, 10, "/", "localhost", false, true)

		c.Redirect(http.StatusFound, "/")
	})

	router.GET("/hello-anyone", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, anyone!"})
	})

	router.GET("/hello-user", authMiddleware(provider), func(c *gin.Context) {
		userInfo := c.MustGet("userInfo").(map[string]interface{})
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello, " + userInfo["name"].(string) + "!",
		})
	})

	router.StaticFile("/", "./index.html")
	router.Run("localhost:8080")
}

func authMiddleware(provider *oidc.Provider) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawIDToken, err := c.Cookie("id_token")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
		idToken, err := verifier.Verify(context.Background(), rawIDToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		var claims struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := idToken.Claims(&claims); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse claims"})
			return
		}

		c.Set("userInfo", claims)
		c.Next()
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
