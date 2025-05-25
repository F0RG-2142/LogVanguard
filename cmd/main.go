package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/F0RG-2142/LogVanguard/internal/parsers"
)

func main() {
	http.HandleFunc("POST /log", logRouter)
	log.Println("Server started on http//localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func logRouter(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Error reading request body:", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}
	r.Body.Close()

	message := string(body)
	message = strings.TrimSpace(message)
	if len(message) == 0 {
		http.Error(w, "unknown", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(strings.NewReader(message))

	// All requests should be JSON, so validate that first
	if len(message) == 0 || message[0] != '{' {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Parse JSON to check structure
	var jsonData map[string]any
	if json.Unmarshal([]byte(message), &jsonData) != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Check if this is a wrapped log (has only "body" field)
	if bodyField, exists := jsonData["body"]; exists && len(jsonData) == 1 {
		// Extract the body content for format checking
		bodyStr, ok := bodyField.(string)
		if !ok {
			http.Error(w, "Body field must be a string", http.StatusBadRequest)
			return
		}

		// Check for syslog format in body (starts with <number>)
		if regexp.MustCompile(`^<\d+>`).MatchString(bodyStr) {
			parsers.SysLogHandler(w, r)
			return
		}

		// Check for TCP format in body (starts with : followed by timestamp)
		if regexp.MustCompile(`^:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}`).MatchString(bodyStr) {
			parsers.TCPLogHandler(w, r)
			return
		}

		// Body field exists but doesn't match known formats
		http.Error(w, "Unknown log format in body field", http.StatusBadRequest)
		return
	}

	// Not a wrapped log, treat as pure JSON log
	parsers.JSONLogHandler(w, r)
}
