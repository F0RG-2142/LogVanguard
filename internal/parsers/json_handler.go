package parsers

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/F0RG-2142/LogVanguard/internal/auth"
	"github.com/F0RG-2142/LogVanguard/internal/database"
	_ "github.com/lib/pq"
)

//parsing logic: unmashal to models.LogEntry
//Logic:
//1. Input example: {
//  "time": "2024-05-10T12:00:03Z",
//	"level": "error",
//  "service": "auth",
//  "msg": "Failed login attempt for user 'alice'",
//  "user": "alice"
//}\
//
//2. Parse with json.Unmashal to models.LogEntry
//
//return: {
// 	"timestamp" : 2024-05-10 12:00:03
//	"severity"	: "error"
//	"source" : "auth"
//	"message" : "Failed login attempt for user 'alice'"
//	"tags" : {
//		"user" : "alice"
//	}
//}

func JSONLogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application-json")
	u, err := url.Parse(r.URL.String())
	if err != nil {
		log.Fatal(err)
	}
	// Get query parameters
	hash := "uierhvnaiuohervoiurhebnohuepiscuoehrg" //for dev purposes,  will remove later
	q := u.Query()
	key := q.Get("api_key")
	err = auth.CheckApiKeyHash(hash, key)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
	hashed_key, err := auth.HashApiKey(key)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusInternalServerError)
	}
	user_id := database.GetUserByKey(r.Context(), hashed_key)
	var req struct {
		Time    time.Time `json:"time"`
		Level   string    `json:"level"`
		Service string    `json:"service"`
		Msg     string    `json:"msg"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//save log to db and send to python service

	//fix or update
	jsonLog, err := json.Marshal(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonLog) // logic to send logs to ml
}
