package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/auth0-samples/auth0-golang-api-samples/01-Quickstart-Go-API/internal/auth"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v3"
	"github.com/auth0/go-jwt-middleware/v3/validator"
)

func PublicHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"message": "Hello from a public endpoint! You don't need to be authenticated to see this.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func PrivateHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"message": "Hello from a private endpoint! You need to be authenticated to see this.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func ScopedHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := jwtmiddleware.GetClaims[*validator.ValidatedClaims](r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Unauthorized."}`))
		return
	}

	customClaims, ok := claims.CustomClaims.(*auth.CustomClaims)
	if !ok || !customClaims.HasScope("read:messages") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"Insufficient scope."}`))
		return
	}

	response := map[string]string{
		"message": "Hello from a private endpoint! You need to be authenticated and have a scope of read:messages to see this.",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
