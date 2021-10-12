package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/rs/cors"

	"01-Authorization-RS256/router"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Print("Error loading .env file")
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
	})

	r := router.New()
	handler := c.Handler(r)

	log.Print("Server listening on http://localhost:3010")
	if err := http.ListenAndServe("0.0.0.0:3010", handler); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}
}
