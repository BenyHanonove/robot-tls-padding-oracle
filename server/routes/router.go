package routes

import "net/http"

// Initialize all API routes
func SetupRoutes(router *http.ServeMux) {
	RegisterAuthRoutes(router)
	RegisterProductRoutes(router)
	RegisterOrderRoutes(router)
	router.HandleFunc("/", handleStatus)
}
