package router

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/codegangsta/negroni"
	"github.com/form3tech-oss/jwt-go"
	"github.com/gorilla/mux"

	"01-Authorization-RS256/middleware"
)

type Response struct {
	Message string `json:"message"`
}

func New() *mux.Router {
	r := mux.NewRouter()

	// This route is always accessible
	r.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := "Hello from a public endpoint! You don't need to be authenticated to see this."
		responseJSON(message, w, http.StatusOK)
	}))

	// This route is only accessible if the user has a valid access_token
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token.
	r.Handle("/api/private", negroni.New(
		negroni.HandlerFunc(middleware.JWT.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)
		}))))

	// This route is only accessible if the user has a valid access_token with the read:messages scope
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token and scope.
	r.Handle(
		"/api/private-scoped",
		negroni.New(
			negroni.HandlerFunc(middleware.JWT.HandlerWithNext),
			negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				token := r.Context().Value("user").(*jwt.Token)

				hasScope := checkScope("read:messages", token)
				if !hasScope {
					message := "Insufficient scope."
					responseJSON(message, w, http.StatusForbidden)
					return
				}

				message := "Hello from a private endpoint! You need to be authenticated to see this."
				responseJSON(message, w, http.StatusOK)
			})),
		),
	)

	return r
}

func checkScope(scope string, token *jwt.Token) bool {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false
	}

	const scopeKey = "scope"
	tokenScope, ok := claims[scopeKey].(string)
	if !ok {
		return false
	}

	result := strings.Split(tokenScope, " ")
	for i := range result {
		if result[i] == scope {
			return true
		}
	}

	return false
}

func responseJSON(message string, w http.ResponseWriter, statusCode int) {
	response := Response{message}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}
