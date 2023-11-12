package helpers

import (
	"fmt"
	"net/http"
)

func Error(response http.ResponseWriter, message string, status int) {
	http.Error(response, fmt.Sprintf(`{ "status": %d, "message": "%s" }`, status, message), status)
}

// The Function That adds the IPs to the IP_ADDRESSES map
