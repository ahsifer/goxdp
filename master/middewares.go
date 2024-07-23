package master

import "net/http"

func (mApp *MasterAPP) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username := r.Header.Get("Username")
		token := r.Header.Get("Token")

		if username == "" || token == "" {
			http.Error(w, "Missing Username or Token", http.StatusUnauthorized)
			return
		}

		expectedToken, exists := mApp.AuthUsers[username]
		if !exists || expectedToken != token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
