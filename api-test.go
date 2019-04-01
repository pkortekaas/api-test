package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/pkortekaas/api-test/controllers"
	"github.com/pkortekaas/api-test/jwtauth"
	"github.com/pkortekaas/api-test/render"
)

// https://github.com/go-chi/chi
// https://itnext.io/structuring-a-production-grade-rest-api-in-golang-c0229b3feedc
// https://github.com/tonyalaribe/todoapi/tree/master/basestructure

type JWTInfo struct {
	Algorithm string
	Issuer    string
	Key       interface{}
}

var (
	tokenAuth *jwtauth.JWTAuth

	jwtMap map[string]JWTInfo

	PrivateKeyRS256String = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYwDLxxa5/7QyH6y77nCRQy
J3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQJARjFLHtuj2zmPrwcBcjja
IS0Q3LKV8pA0LoCS+CdD+4QwCxeKFq0yEMZtMvcQOfqo9x9oAywFClMSlLRyl7ng
gQIhAOyerGbcdQxxwjwGpLS61Mprf4n2HzjwISg20cEEH1tfAiEAy9dXmgQpDPir
C6Q9QdLXpNgSB+o5CDqfor7TTyTCovsCIQDNCfpu795luDYN+dvD2JoIBfrwu9v2
ZO72f/pm/YGGlQIgUdRXyW9kH13wJFNBeBwxD27iBiVj0cbe8NFUONBUBmMCIQCN
jVK4eujt1lm/m60TlEhaWBC3p+3aPT2TqFPUigJ3RQ==
-----END RSA PRIVATE KEY-----
`

	PublicKeyRS256String = `-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALxo3PCjFw4QjgOX06QCJIJBnXXNiEYw
DLxxa5/7QyH6y77nCRQyJ3x3UwF9rUD0RCsp4sNdX5kOQ9PUyHyOtCUCAwEAAQ==
-----END PUBLIC KEY-----
`
)

func init() {
	kid := "1234"
	jwtMap = map[string]JWTInfo{kid: {Algorithm: "RS256", Issuer: "webtoken", Key: getPublicKey(PublicKeyRS256String)}}

	tokenAuth = jwtauth.NewWithParser(
		&jwt.Parser{
			ValidMethods: []string{"RS256", "RS384", "RS512"},
		},
		getPrivateKey(PrivateKeyRS256String),
		keyFunc)

	// Create the Claims
	claims := jwt.StandardClaims{
		Issuer:    jwtMap[kid].Issuer,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Second * 30).Unix(),
	}
	header := map[string]interface{}{"kid": kid}
	_, tokenString, _ := tokenAuth.Encode("RS256", claims, header)
	fmt.Printf("http://localhost:3000/api/v1?jwt=%s\n\n", tokenString)
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

func keyFunc(token *jwt.Token) (interface{}, error) {
	if jwt, ok := jwtMap[token.Header["kid"].(string)]; ok {
		return jwt.Key, nil
	} else {
		return nil, errors.New("keyFunc: not found")
	}
}

func authenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, claims, err := jwtauth.FromContext(r.Context())

		if err != nil {
			switch err {
			default:
				http.Error(w, http.StatusText(401), 401)
				return
			case jwtauth.ErrExpired:
				http.Error(w, "Token expired", 401)
				return
			case jwtauth.ErrUnauthorized:
				http.Error(w, http.StatusText(401), 401)
				return
			}
		}

		if token == nil || !token.Valid {
			http.Error(w, http.StatusText(401), 401)
			return
		}

		jwt, ok := jwtMap[token.Header["kid"].(string)]

		if !ok || token.Method.Alg() != jwt.Algorithm || claims["iss"] != jwt.Issuer {
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

func getPrivateKey(keyString string) *rsa.PrivateKey {
	privateKeyBlock, _ := pem.Decode([]byte(PrivateKeyRS256String))
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)

	if err != nil {
		log.Fatalf(err.Error())
	}

	return privateKey
}

func getPublicKey(keyString string) interface{} {
	publicKeyBlock, _ := pem.Decode([]byte(keyString))
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)

	if err != nil {
		log.Fatalf(err.Error())
	}

	return publicKey
}
