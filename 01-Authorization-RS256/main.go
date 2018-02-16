package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	auth0 "github.com/auth0-community/go-auth0"
	"github.com/gorilla/mux"
	jose "gopkg.in/square/go-jose.v2"
	jwt "gopkg.in/square/go-jose.v2/jwt"
	"github.com/joho/godotenv"
	"log"
	"os"
)

type Response struct {
	Message string `json:"message"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Print("Error loading .env file")
	}

	r := mux.NewRouter()

	// This route is always accessible
	r.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Message: "Hello from a public endpoint! You don't need to be authenticated to see this.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}))

	// This route is only accessible if the user has a valid access_token
	// We are wrapping the checkJwt middleware around the handler function which will check for a valid token.
	r.Handle("/api/private", checkJwt(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := Response{
			Message: "Hello from a private endpoint! You need to be authenticated to see this.",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)

	})))

	// This route is only accessible if the user has a valid access_token with the read:messages scope
	// We are wrapping the checkJwt middleware around the handler function which will check for a
	// valid token and scope.
	r.Handle("/api/private-scoped", checkJwt(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ensure the token has the correct scope
		JWKS_URI := "https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json"
		client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: JWKS_URI})
		aud := os.Getenv("AUTH0_AUDIENCE")
		audience := []string{aud}

		var AUTH0_API_ISSUER = "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
		configuration := auth0.NewConfiguration(client, audience, AUTH0_API_ISSUER, jose.RS256)
		validator := auth0.NewValidator(configuration)
		token, _ := validator.ValidateRequest(r)
		result := checkScope(r, validator, token)
		if result == true {
			response := Response{
				Message: "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(response)
		} else {
			response := Response{
				Message: "You do not have the read:messages scope.",
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(response)

		}

	})))

	fmt.Println("Listening on http://localhost:3010")
	http.ListenAndServe("0.0.0.0:3010", r)
}

func checkJwt(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		JWKS_URI := "https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json"
		client := auth0.NewJWKClient(auth0.JWKClientOptions{URI: JWKS_URI})
		aud := os.Getenv("AUTH0_AUDIENCE")
		audience := []string{aud}

		var AUTH0_API_ISSUER = "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
		configuration := auth0.NewConfiguration(client, audience, AUTH0_API_ISSUER, jose.RS256)
		validator := auth0.NewValidator(configuration)

		_, err := validator.ValidateRequest(r)

		if err != nil {
			fmt.Println("Token is not valid or missing token")

			response := Response{
				Message: "Missing or invalid token.",
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)

		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func checkScope(r *http.Request, validator *auth0.JWTValidator, token *jwt.JSONWebToken) bool {
	claims := map[string]interface{}{}
	err := validator.Claims(r, token, &claims)

	if err != nil {
		fmt.Println(err)
		return false
	}

	if claims["scope"] != nil && strings.Contains(claims["scope"].(string), "read:messages") {
		return true
	} else {
		return false
	}
}
