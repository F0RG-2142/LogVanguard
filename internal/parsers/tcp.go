package parsers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/F0RG-2142/LogVanguard/models"
)

// file tailer
//Logic:
//1. Input example: 2024-05-10 12:00:03 [ERROR] Failed login attempt for user 'alice' from IP 192.168.1.100
//2. Parse with line-by-line regex or custom parser to models.LogEntry
//3. return: {
// 	"timestamp" : 2024-05-10 12:00:03
//	"severity"	: "error"
//	"source" : "auth"
//	"message" : "Failed login attempt for user 'alice'"
//	"tags" : {
//		"ip" : "192.168.1.100"
//	}
//}

var fileSeverityMap = map[string]string{
	"ERROR": "error",
	"WARN":  "warn",
	"INFO":  "info",
	"DEBUG": "debug",
}

func TCPLogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	//Decode req
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//Parse log in request
	log, err := parseTCPLog(req.Body)
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

// parseTCPLog parses a TCP log message into a LogEntry
func parseTCPLog(message string) (models.LogEntry, error) {
	// Regular expression for the TCP log format
	re := regexp.MustCompile(`^:(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$`)
	matches := re.FindStringSubmatch(message)
	if len(matches) != 4 {
		return models.LogEntry{}, fmt.Errorf("invalid TCP log message format")
	}

	// Extract components
	timestampStr, severityStr, msg := matches[1], matches[2], matches[3]

	// Parse timestamp (assume UTC since no timezone is specified)
	timestamp, err := time.Parse("2006-01-02 15:04:05", timestampStr)
	if err != nil {
		return models.LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
	}
	// Ensure UTC for JSON serialization
	timestamp = timestamp.UTC()

	// Normalize severity
	severity, ok := fileSeverityMap[strings.ToUpper(severityStr)]
	if !ok {
		severity = "unknown"
	}

	// Extract tags (e.g., user and IP)
	tags := make(map[string]string)
	userRe := regexp.MustCompile(`user '(\w+)'`)
	ipRe := regexp.MustCompile(`from IP (\d+\.\d+\.\d+\.\d+)`)
	if userMatch := userRe.FindStringSubmatch(msg); len(userMatch) == 2 {
		tags["user"] = userMatch[1]
	}
	if ipMatch := ipRe.FindStringSubmatch(msg); len(ipMatch) == 2 {
		tags["ip"] = ipMatch[1]
	}

	// Create LogEntry
	return models.LogEntry{
		Timestamp: timestamp,
		Severity:  severity,
		Source:    "unknown", // No source specified in the message
		Message:   msg,
	}, nil
}
