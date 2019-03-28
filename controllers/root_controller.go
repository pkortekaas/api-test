package controllers

import (
	"api-test/jwtauth"
	"api-test/render"
	"net/http"
	"time"

	"github.com/go-chi/chi"
)

func RootController() *chi.Mux {
	router := chi.NewRouter()
	router.Get("/", get)
	return router
}

func get(w http.ResponseWriter, r *http.Request) {
	token, claims, _ := jwtauth.FromContext(r.Context())
	response := make(map[string]string)
	response["KeyId"] = token.Header["kid"].(string)
	response["Issuer"] = claims["iss"].(string)
	response["ExpiresAt"] = time.Unix(int64(claims["exp"].(float64)), 0).Format(time.RFC3339)
	response["message"] = "Hello, world!"
	render.JSON(w, r, response)
}
