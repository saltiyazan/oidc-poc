package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

var (
	clientID       = ""
	clientSecret   = ""
	redirectURI    = "http://localhost:3000/callback"
	AUTH0_AUDIENCE = "https://oidc-poc.com"

	provider, _ = oidc.NewProvider(context.Background(), "")

	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}
)

var (
	userKey      = "user"
	store        = sessions.NewCookieStore([]byte("your-secret-key"))
	jwtValidator *validator.Validator
)

type UserClaims struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type CustomClaims struct {
	Scope string `json:"scope"`
}

func (c CustomClaims) Validate(ctx context.Context) error {
	return nil
}

func init() {
	issuerURL, err := url.Parse("")
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	// Create the JWKS caching provider
	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)
	// Initialize the JWT validator
	jwtValidator, err = validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		[]string{AUTH0_AUDIENCE},
	)
	if err != nil {
		log.Fatalf("Failed to initialize JWT validator: %v", err)
	}
	gob.Register(&oidc.IDToken{})
	gob.Register(UserClaims{}) // Register the named struct
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)
	http.HandleFunc("/logout", logoutHandler)

	log.Println("Starting server on :3000")
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "auth-session")

	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Check for Bearer token in Authorization header
	token := r.Header.Get("Authorization")
	if token != "" && strings.HasPrefix(token, "Bearer ") {
		// Extract the token
		accessToken := token[len("Bearer "):]

		// Validate the access token (you can add your validation logic here)
		if isValidToken(accessToken) { // Implement your token validation logic
			// If valid, display user info (you can also decode claims here if needed)
			fmt.Fprintf(w, "<h2>Access Token Valid!</h2>")
			fmt.Fprint(w, "<a href=\"/logout\">Logout</a>")
			return
		}
	}

	if user, ok := session.Values[userKey].(UserClaims); ok {
		// Display user info with an HTML logout link
		fmt.Fprintf(w, "<h2>Welcome, %s!</h2>", user.Email)
		fmt.Fprint(w, "<a href=\"/logout\">Logout</a>")
	} else {
		log.Println("Unauthenticated user accessed the index page")
		// Display an HTML login link
		fmt.Fprint(w, "<a href=\"/login\">Login with Auth0</a>")
	}
}

func isValidToken(token string) bool {
	_, err := jwtValidator.ValidateToken(context.Background(), token)
	if err != nil {
		log.Println("Invalid token:", err)
	}
	return err == nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	clientType := r.URL.Query().Get("client_type")

	if clientType == "api" {
		// API client login - using Client Credentials Grant

		clientCredentialsConfig := &oauth2.Config{
			ClientID:     "HY3RRFEsvUb9XsyXrynVWjC63blo7cnL",
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				TokenURL: "",
			},
			Scopes: []string{"openid", "profile", "email"},
		}

		// Form values for client credentials grant type
		values := url.Values{}
		values.Set("grant_type", "client_credentials")
		values.Set("client_id", "")
		values.Set("client_secret", "")
		values.Set("audience", AUTH0_AUDIENCE) // Set your API audience (the identifier for your API)

		// Make the token request to Auth0
		resp, err := http.PostForm(clientCredentialsConfig.Endpoint.TokenURL, values)
		if err != nil {
			http.Error(w, "Failed to get access token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Read response body to retrieve the access token
		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)

		if resp.StatusCode != http.StatusOK {
			http.Error(w, fmt.Sprintf("Failed to get access token: %v", result), http.StatusInternalServerError)
			return
		}

		// Send the access token as JSON response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)

	} else {
		// Web-based login (current behavior)
		b := make([]byte, 32)
		rand.Read(b)
		state := base64.StdEncoding.EncodeToString(b)

		session, _ := store.Get(r, "auth-session")
		session.Values["state"] = state
		session.Save(r, w)

		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
	}
}

func oauthLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state, save to session, and redirect for OAuth login
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, _ := store.Get(r, "auth-session")
	session.Values["state"] = state
	session.Save(r, w)

	log.Println("Redirecting user to Auth0 for API authentication")
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func oidcLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state, save to session, and redirect for OIDC login
	b := make([]byte, 32)
	rand.Read(b)
	state := base64.StdEncoding.EncodeToString(b)

	session, _ := store.Get(r, "auth-session")
	session.Values["state"] = state
	session.Save(r, w)

	log.Println("Redirecting user to Auth0 for OIDC authentication")
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		log.Printf("Auth0 authorization error: %s", errMsg)
		http.Error(w, fmt.Sprintf("Auth0 authorization error: %s", errMsg), http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "auth-session")
	if session.Values["state"] != r.URL.Query().Get("state") {
		log.Println("State mismatch in callback")
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	delete(session.Values, "state")
	session.Save(r, w)

	oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("Failed to exchange token: %s", err.Error())
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Println("No id_token field in oauth2 token.")
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("Failed to verify ID Token: %s", err.Error())
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims UserClaims
	if err := idToken.Claims(&claims); err != nil {
		log.Printf("Failed to parse claims: %s", err.Error())
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values[userKey] = claims
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %s", err.Error())
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	log.Printf("User %s successfully logged in", claims.Email)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Clear the session
	session, _ := store.Get(r, "auth-session")
	if user, ok := session.Values[userKey].(UserClaims); ok {
		log.Printf("User %s logged out", user.Email)
	}

	delete(session.Values, userKey)
	err := session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %s", err.Error())
	}

	// Create the logout URL for Auth0
	logoutURL, err := url.Parse("")
	if err != nil {
		http.Error(w, "Error parsing logout URL", http.StatusInternalServerError)
		return
	}

	// Determine the scheme (http or https)
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Set the return URL to redirect to after logout
	returnTo, err := url.Parse(scheme + "://" + r.Host)
	if err != nil {
		http.Error(w, "Error parsing return URL", http.StatusInternalServerError)
		return
	}

	// Add query parameters for Auth0 logout
	parameters := url.Values{}
	parameters.Add("returnTo", returnTo.String())
	parameters.Add("client_id", clientID)
	logoutURL.RawQuery = parameters.Encode()

	log.Println("Redirecting user to Auth0 for logout")
	// Redirect the user to Auth0's logout URL
	http.Redirect(w, r, logoutURL.String(), http.StatusTemporaryRedirect)
}
