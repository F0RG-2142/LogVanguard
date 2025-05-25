package server

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
