package router

import (
	"net/http"
	"strings"

	"github.com/form3tech-oss/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"01-Authorization-RS256/middleware"
)

// New sets up our routes and returns a *gin.Engine.
func New() *gin.Engine {
	router := gin.Default()

	router.Use(cors.New(
		cors.Config{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowCredentials: true,
			AllowHeaders:     []string{"Authorization"},
		},
	))

	// This route is always accessible.
	router.Any("/api/public", func(ctx *gin.Context) {
		response := map[string]string{
			"message": "Hello from a public endpoint! You don't need to be authenticated to see this.",
		}
		ctx.JSON(http.StatusOK, response)
	})

	// This route is only accessible if the user has a valid access_token.
	router.GET(
		"/api/private",
		middleware.EnsureValidToken(),
		func(ctx *gin.Context) {
			response := map[string]string{
				"message": "Hello from a private endpoint! You need to be authenticated to see this.",
			}
			ctx.JSON(http.StatusOK, response)
		},
	)

	// This route is only accessible if the user has a
	// valid access_token with the read:messages scope.
	router.GET(
		"/api/private-scoped",
		middleware.EnsureValidToken(),
		func(ctx *gin.Context) {
			token := ctx.Request.Context().Value("user").(*jwt.Token)

			hasScope := checkScope("read:messages", token)
			if !hasScope {
				response := map[string]string{"message": "Insufficient scope."}
				ctx.JSON(http.StatusForbidden, response)
				return
			}

			response := map[string]string{
				"message": "Hello from a private endpoint! You need to be authenticated to see this.",
			}
			ctx.JSON(http.StatusOK, response)
		},
	)

	return router
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
