package middleware

import (
	"fmt"
	"net/http"
)

// Log incoming HTTP requests
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fmt.Printf("[REQUEST] %s %s\n", request.Method, request.URL.Path)
		next.ServeHTTP(response, request)
	})
}
