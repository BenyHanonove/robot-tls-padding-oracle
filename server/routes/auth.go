package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Register authentication API endpoints
func RegisterAuthRoutes(router *http.ServeMux) {
	router.HandleFunc("/auth/login", handleLogin)
	router.HandleFunc("/auth/logout", handleLogout)
}

// Handle user authentication requests
func handleLogin(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials map[string]string
	json.NewDecoder(request.Body).Decode(&credentials)
	fmt.Printf("[AUTH] Login Attempt: %v\n", credentials)

	// Return successful login status
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(map[string]string{
		"status":  "success",
		"message": "Logged in",
	})
}

// Handle session termination requests
func handleLogout(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("[AUTH] Logout")

	// Return successful logout status
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(map[string]string{
		"status":  "success",
		"message": "Logged out",
	})
}
