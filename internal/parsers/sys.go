package parsers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/F0RG-2142/LogVanguard/models"
)

//get and process tcp syslogs
//rfc5424 comliant syslogs only
//Logic:
//1. Input example: <12>1 2024-05-10T12:00:03Z mymachine app - - [meta sequenceId="1"] Failed login attempt for user 'alice'
//2. Parse with line-by-line regex or custom parser to models.LogEntry
//3. return: {
// 	"timestamp" : 2024-05-10T12:00:03Z
//	"severity"	: "error"
//	"source" : "auth"
//	"message" : "Failed login attempt for user 'alice'"
//	"tags" : {
//		"ip" : "192.168.1.100"
//	}
//}

var tcpSeverityMap = map[int]string{
	0: "error", // Emergency
	1: "error", // Alert
	2: "error", // Critical
	3: "error", // Error
	4: "warn",  // Warning
	5: "info",  // Notice
	6: "info",  // Informational
	7: "debug", // Debug
}

func SysLogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	//Decode req
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	//parse log
	log, err := parseSyslog(req.Body)
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

// parseSyslog parses a syslog message into a LogEntry
func parseSyslog(message string) (models.LogEntry, error) {
	// Regular expression for RFC 5424 syslog format
	re := regexp.MustCompile(`^<(\d+)>\d+ (\S+) (\S+) (\S+) - (\[.*?\]) (.*)$`)
	matches := re.FindStringSubmatch(message)
	if len(matches) != 7 {
		return models.LogEntry{}, fmt.Errorf("invalid syslog message format")
	}

	// Extract components
	priStr, timestampStr, _, appName, structuredData, msg := matches[1], matches[2], matches[3], matches[4], matches[5], matches[6]

	// Parse PRI to get severity
	pri, err := strconv.Atoi(priStr)
	if err != nil {
		return models.LogEntry{}, fmt.Errorf("invalid PRI value: %v", err)
	}
	severityValue := pri % 8
	severity, ok := tcpSeverityMap[severityValue]
	if !ok {
		severity = "unknown"
	}

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339Nano, timestampStr)
	if err != nil {
		return models.LogEntry{}, fmt.Errorf("invalid timestamp: %v", err)
	}

	// Parse structured data (e.g., [PID=1234])
	tags := make(map[string]string)
	if structuredData != "[-]" {
		sdRe := regexp.MustCompile(`\[(\w+)=(\S+)\]`)
		sdMatches := sdRe.FindAllStringSubmatch(structuredData, -1)
		for _, match := range sdMatches {
			if len(match) == 3 {
				tags[match[1]] = match[2]
			}
		}
	}

	// Create LogEntry
	return models.LogEntry{
		Timestamp: timestamp,
		Severity:  severity,
		Source:    appName,
		Message:   msg,
	}, nil
}
