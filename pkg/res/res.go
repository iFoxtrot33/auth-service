package res

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func Json(w http.ResponseWriter, data any, statusCode int) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonData)
	fmt.Println("Sending JSON response:", string(jsonData))
}
