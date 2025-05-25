package parsers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/F0RG-2142/LogVanguard/models"
)

//get and process http logs
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
	var req string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	log, err := parseJSONLog(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
	//fix or update
	jsonLog, err := json.Marshal(log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(jsonLog) // logic to send logs to ml
}

// severityMap normalizes severity strings to info/warn/error/debug
var severityMap = map[string]string{
	"ERROR":   "error",
	"ERR":     "error",
	"WARN":    "warn",
	"WARNING": "warn",
	"INFO":    "info",
	"NOTICE":  "info",
	"DEBUG":   "debug",
}

// timestamp severity, message, sourceKeys are common keys for timestamps
var timestampKeys = []string{"time", "timestamp", "date", "created_at"}
var severityKeys = []string{"level", "severity", "loglevel"}
var messageKeys = []string{"msg", "message", "description", "event"}
var sourceKeys = []string{"app", "source", "service", "application"}

// parseJSONLog parses a JSON log message into a LogEntry
func parseJSONLog(jsonStr string) (models.LogEntry, error) {
	// Parse JSON into a generic map
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return models.LogEntry{}, fmt.Errorf("invalid JSON: %v", err)
	}

	entry := models.LogEntry{
		Source: "unknown",
	}

	// Parse timestamp
	for _, key := range timestampKeys {
		if val, ok := raw[key]; ok {
			if timeStr, ok := val.(string); ok {
				// Try multiple time formats
				for _, layout := range []string{
					time.RFC3339Nano,
					time.RFC3339,
					"2006-01-02 15:04:05",
					"2006-01-02T15:04:05",
				} {
					if t, err := time.Parse(layout, timeStr); err == nil {
						entry.Timestamp = t.UTC()
						break
					}
				}
				if entry.Timestamp.IsZero() {
					return models.LogEntry{}, fmt.Errorf("invalid timestamp format for %s: %v", key, val)
				}
				delete(raw, key)
				break
			}
		}
	}
	if entry.Timestamp.IsZero() {
		// Fallback to current time if no timestamp is found
		entry.Timestamp = time.Now().UTC()
	}

	// Parse severity
	for _, key := range severityKeys {
		if val, ok := raw[key]; ok {
			if severityStr, ok := val.(string); ok {
				entry.Severity = severityMap[strings.ToUpper(severityStr)]
				if entry.Severity == "" {
					entry.Severity = "unknown"
				}
				delete(raw, key)
				break
			}
		}
	}
	if entry.Severity == "" {
		entry.Severity = "unknown"
	}

	// Parse source
	for _, key := range sourceKeys {
		if val, ok := raw[key]; ok {
			if sourceStr, ok := val.(string); ok {
				entry.Source = sourceStr
				delete(raw, key)
				break
			}
		}
	}

	// Parse message
	for _, key := range messageKeys {
		if val, ok := raw[key]; ok {
			if msgStr, ok := val.(string); ok {
				entry.Message = msgStr
				delete(raw, key)
				break
			}
		}
	}
	if entry.Message == "" {
		// Fallback: use JSON string representation of remaining fields
		if msgBytes, err := json.Marshal(raw); err == nil {
			entry.Message = string(msgBytes)
		} else {
			entry.Message = "No message found"
		}
	}

	return entry, nil
}
