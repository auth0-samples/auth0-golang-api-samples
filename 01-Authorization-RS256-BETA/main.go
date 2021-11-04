package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"

	"01-Authorization-RS256/router"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading the .env file: %v", err)
	}

	rtr := router.New()

	log.Print("Server listening on http://localhost:3010")
	if err := http.ListenAndServe("0.0.0.0:3010", rtr); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}
}
