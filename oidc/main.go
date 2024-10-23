package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

// Set these variables with your provider's details
var (
	clientID     = ""
	clientSecret = ""
	redirectURL  = "http://localhost:8080/callback"              // Redirect URL after GitHub login
	authURL      = "https://github.com/login/oauth/authorize"    // GitHub OAuth2 authorization URL
	tokenURL     = "https://github.com/login/oauth/access_token" // GitHub OAuth2 token URL
)

var oauth2Config = oauth2.Config{
	ClientID:     clientID,
	ClientSecret: clientSecret,
	RedirectURL:  redirectURL,
	Endpoint: oauth2.Endpoint{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	},
	Scopes: []string{"read:user", "user:email"}, // Scopes for GitHub API access
}

func main() {
	http.HandleFunc("/", handleMain)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	fmt.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleMain(w http.ResponseWriter, r *http.Request) {
	// Serve a simple HTML page with a "Login" button
	html := `<html>
                <body>
                    <h1>Welcome to GitHub OAuth2 Demo</h1>
                    <a href="/login">Login with GitHub</a>
                </body>
             </html>`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect user to GitHub's OAuth2 login page
	http.Redirect(w, r, oauth2Config.AuthCodeURL("random-state"), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Retrieve authorization code from the request
	code := r.URL.Query().Get("code")

	// Exchange authorization code for tokens
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Use the access token to fetch user information from GitHub
	client := oauth2Config.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to parse user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Greet the user after successful login
	html := fmt.Sprintf(`<html>
                            <body>
                                <h1>Hello, %s!</h1>
                                <p>Email: %s</p>
                            </body>
                         </html>`, userInfo.Login, userInfo.Email)
	fmt.Fprint(w, html)
}
