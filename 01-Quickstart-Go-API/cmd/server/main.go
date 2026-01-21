package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/auth0-samples/auth0-golang-api-samples/01-Quickstart-Go-API/internal/auth"
	"github.com/auth0-samples/auth0-golang-api-samples/01-Quickstart-Go-API/internal/config"
	"github.com/auth0-samples/auth0-golang-api-samples/01-Quickstart-Go-API/internal/handlers"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	cfg, err := config.LoadAuthConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	jwtValidator, err := auth.NewValidator(cfg.Domain, cfg.Audience)
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}

	middleware, err := auth.NewMiddleware(jwtValidator)
	if err != nil {
		log.Fatalf("Failed to create middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/public", handlers.PublicHandler)
	mux.Handle("/api/private", middleware.CheckJWT(http.HandlerFunc(handlers.PrivateHandler)))
	mux.Handle("/api/private-scoped", middleware.CheckJWT(http.HandlerFunc(handlers.ScopedHandler)))

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Println("Server starting on :8080")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}
