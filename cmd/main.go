package main

import (
	"log"
	"net/http"

	"github.com/F0RG-2142/LogVanguard/internal/parsers"
)

func main() {
	http.HandleFunc("POST api/v1/log/{api_key}", parsers.JSONLogHandler)
	log.Println("Server started on http//localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
