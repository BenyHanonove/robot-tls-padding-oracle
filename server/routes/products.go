package routes

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Product data structure definition
type Product struct {
	ID    int     `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

// Static list of available products
var productList = []Product{
	{ID: 1, Name: "Laptop", Price: 1000},
	{ID: 2, Name: "Mouse", Price: 20},
	{ID: 3, Name: "Keyboard", Price: 50},
}

// Register product API endpoints
func RegisterProductRoutes(router *http.ServeMux) {
	router.HandleFunc("/products/", handleProducts)
}

// Handle product retrieval requests
func handleProducts(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	urlSegments := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	
	// Return entire product list
	if len(urlSegments) == 1 {
		response.Header().Set("Content-Type", "application/json")
		json.NewEncoder(response).Encode(productList)
		return
	}

	// Return specific product details
	if len(urlSegments) == 2 {
		productID, err := strconv.Atoi(urlSegments[1])
		if err == nil {
			for _, product := range productList {
				if product.ID == productID {
					response.Header().Set("Content-Type", "application/json")
					json.NewEncoder(response).Encode(product)
					return
				}
			}
		}
	}

	http.Error(response, "Product not found", http.StatusNotFound)
}
