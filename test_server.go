package main

import (
	"fmt"
	"net/http"
)

// Simple test server for testing the ShieldCLI proxy
func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from test server!\nRequest: %s %s\n", r.Method, r.RequestURI)
	})

	http.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "ok", "data": "test data"}`)
	})

	fmt.Println("Test server listening on :3000")
	http.ListenAndServe(":3000", nil)
}
