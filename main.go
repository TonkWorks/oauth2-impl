package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	codeMap := make(map[string]string)

	// oauth2 implementation
	router.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		// Should return authorization code back to the user
		v := r.URL.Query()

		redirect_uri := v.Get("redirect_uri")
		scope := v.Get("scope")

		accessToken := GenerateSecureToken(8)
		codeMap[accessToken] = "SO AND SO"
		newUrl := fmt.Sprintf("%v#access_token=%v&scope=%v&token_type=bearer", redirect_uri, accessToken, scope)
		http.Redirect(w, r, newUrl, http.StatusSeeOther)
	})

	router.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%v\n", "AAAAAAAAAAAAAAAAAAAAA")

	})

	router.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=mocktoken&scope=user&token_type=bearer"))
	})

	// some mock things.
	router.HandleFunc("/jwts/{path:.*}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		claims := customClaims{
			Username: vars["path"],
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: 15000,
				Issuer:    "nameOfWebsiteHere",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		key := []byte("AllYourBase")
		ss, err := token.SignedString(key)
		if err != nil {
			log.Printf("%v", err)
		}
		fmt.Fprintf(w, "%v\n", ss)
	})

	fmt.Println("GO REST server running on http://localhost:8000 ")
	log.Fatal(http.ListenAndServe(":8000", router))
}

type customClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
