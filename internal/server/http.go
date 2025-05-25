package server

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
