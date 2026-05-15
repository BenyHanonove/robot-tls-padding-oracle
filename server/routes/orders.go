package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Register order API endpoints
func RegisterOrderRoutes(router *http.ServeMux) {
	router.HandleFunc("/orders/", handleOrder)
}

// Handle new order submissions
func handleOrder(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var orderDetails interface{}
	json.NewDecoder(request.Body).Decode(&orderDetails)
	fmt.Printf("[ORDER] New Order: %v\n", orderDetails)

	// Return successful order response
	response.Header().Set("Content-Type", "application/json")
	json.NewEncoder(response).Encode(map[string]interface{}{
		"status":   "success",
		"order_id": 123,
	})
}
