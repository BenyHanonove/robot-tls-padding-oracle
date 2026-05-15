package routes

import (
	"fmt"
	"net/http"
)

// Handle system status check
func handleStatus(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(response, `{"status": "online", "message": "Vulnerable ROBOT Go Server"}`)
}
