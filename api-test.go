package main

import (
	"api-test/controllers"
	"api-test/jwtauth"
	"api-test/render"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

// https://github.com/go-chi/chi
// https://itnext.io/structuring-a-production-grade-rest-api-in-golang-c0229b3feedc
// https://github.com/tonyalaribe/todoapi/tree/master/basestructure

var tokenAuth *jwtauth.JWTAuth

type JWTInfo struct {
	Algorithm string
	Issuer    string
	Key       interface{}
}

var Keys map[string]JWTInfo

// Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6IjEyMzQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE1NTM3MTMwMDUsImlhdCI6MTU1MzcxMjQwNSwiaXNzIjoid2VidG9rZW4ifQ.NrpWNLv_KcdjOSK6GSsvRcaRj6tIGgCu7RKqKmp9Q2k
func init() {

	kid := "1234"
	Keys = map[string]JWTInfo{kid: {Algorithm: "HS256", Issuer: "webtoken", Key: []byte("secret")}}

	tokenAuth = jwtauth.NewWithParser(
		Keys[kid].Algorithm,
		&jwt.Parser{
			ValidMethods: []string{"HS256", "RS256", "RS512"},
		},
		Keys[kid].Key,
		nil, keyFunc)

	// Create the Claims
	claims := jwt.StandardClaims{
		Issuer:    Keys[kid].Issuer,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Second * 20).Unix(),
	}
	header := map[string]interface{}{"kid": kid}
	_, tokenString, _ := tokenAuth.Encode(claims, header)
	fmt.Printf("http://localhost:3000/api/v1?jwt=%s\n\n", tokenString)
}

func setupRoutes() *chi.Mux {
	router := chi.NewRouter()

	router.Use(
		jwtauth.Verifier(tokenAuth),                   // Seek, verify and validate JWT tokens
		render.SetContentType(render.ContentTypeJSON), // Set content-Type headers as application/json
		middleware.Logger,                             // Log API request calls
		middleware.DefaultCompress,                    // Compress results, mostly gzipping assets and json
		middleware.RedirectSlashes,                    // Redirect slashes to no slash URL versions
		middleware.Recoverer,                          // Recover from panics without crashing server
		authenticator,                                 // Handle valid / invalid tokens.
	)

	router.Route("/api/v1", func(r chi.Router) {
		r.Mount("/", controllers.RootController())
	})

	return router
}

func main() {
	router := setupRoutes()

	walkFunc := func(method string, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		log.Printf("%s %s\n", method, route) // Walk and print out all routes
		return nil
	}
	if err := chi.Walk(router, walkFunc); err != nil {
		log.Panicf("Logging err: %s\n", err.Error()) // panic if there is an error
	}

	log.Fatal(http.ListenAndServe(":3000", router))
}

func keyFunc(t *jwt.Token) (interface{}, error) {
	return Keys[t.Header["kid"].(string)].Key, nil
}

func authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		if token == nil || !token.Valid {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		usr := claims["iss"]
		kid := token.Header["kid"]
		fmt.Println(token.Method.Alg(), kid, usr)

		// Token is authenticated, pass it through
		next.ServeHTTP(w, r)
	})
}
