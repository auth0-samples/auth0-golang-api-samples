package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/auth0/go-jwt-middleware"
	"github.com/auth0/go-jwt-middleware/validate/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const signatureAlgorithm = "RS256"

// Ensure our CustomClaims implement the jwtgo.CustomClaims interface.
var _ jwtgo.CustomClaims = &CustomClaims{}

// CustomClaims holds our custom claims for the *jwt.Token.
type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

// Validate our *CustomClaims.
func (c CustomClaims) Validate(_ context.Context) error {
	expectedAudience := os.Getenv("AUTH0_AUDIENCE")
	if c.Audience != expectedAudience {
		return fmt.Errorf("token claims validation failed: unexpected audience %q", c.Audience)
	}

	expectedIssuer := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"
	if c.Issuer != expectedIssuer {
		return fmt.Errorf("token claims validation failed: unexpected issuer %q", c.Issuer)
	}

	return nil
}

// HasScope checks whether our claims have a specific scope.
func (c CustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}

	return false
}

// EnsureValidToken is a gin.HandlerFunc middleware that will check the validity of our JWT.
func EnsureValidToken() gin.HandlerFunc {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		certificate, err := getPEMCertificate(token)
		if err != nil {
			return token, err
		}

		return jwt.ParseRSAPublicKeyFromPEM([]byte(certificate))
	}

	customClaims := func() jwtgo.CustomClaims {
		return &CustomClaims{}
	}

	validator, err := jwtgo.New(
		keyFunc,
		signatureAlgorithm,
		jwtgo.WithCustomClaims(customClaims),
	)
	if err != nil {
		log.Fatalf("Failed to set up the jwt validator")
	}

	m := jwtmiddleware.New(validator.ValidateToken)

	return func(ctx *gin.Context) {
		var encounteredError = true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.Request = r
			ctx.Next()
		}

		m.CheckJWT(handler).ServeHTTP(ctx.Writer, ctx.Request)

		if encounteredError {
			ctx.AbortWithStatusJSON(
				http.StatusUnauthorized,
				map[string]string{"message": "Failed to validate JWT."},
			)
		}
	}
}

type (
	jwks struct {
		Keys []jsonWebKeys `json:"keys"`
	}

	jsonWebKeys struct {
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		Use string   `json:"use"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	}
)

func getPEMCertificate(token *jwt.Token) (string, error) {
	response, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	var jwks jwks
	if err = json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return "", err
	}

	var cert string
	for _, key := range jwks.Keys {
		if token.Header["kid"] == key.Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----"
			break
		}
	}

	if cert == "" {
		return cert, errors.New("unable to find appropriate key")
	}

	return cert, nil
}
