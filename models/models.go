package models

import "time"

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"` // info/warn/error/debug
	Source    string    `json:"source"`   // app name or file path
	Message   string    `json:"message"`
}
