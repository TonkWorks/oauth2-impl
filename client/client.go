package main

import (
	"context"
	"log"
	"net/http"
	"fmt"
	"time"
	"encoding/base64"
	"crypto/rand"
	"golang.org/x/oauth2"
)

const (
	authServerURL = "http://supercomputer:5556/dex"
)

var (
	config = oauth2.Config{
		ClientID:     "example-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",
		Scopes:       []string{"openid"},
		RedirectURL:  "http://supercomputer:5555/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  authServerURL + "/auth",
			TokenURL: authServerURL + "/token",
		},
	}
)

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// We have a jwtCookie!
		jwtCookie, _ := r.Cookie("jwt")
		if jwtCookie != nil {
			data, _ := base64.StdEncoding.DecodeString(jwtCookie.Value)
			if string(data) != "" {
				r.Header.Set("Authorization", "Bearer " + string(data))
				fmt.Fprintf(w, "UserInfo: %s\n", data)
				return
			}
		}

		oauthState := generateStateOauthCookie(w)
		u := config.AuthCodeURL(oauthState)
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
		return
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		// remove any previous jwt cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Expires: time.Unix(0, 0),
		})
		fmt.Fprintf(w, "logged out")
		return
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// remove any previous jwt cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "jwt",
			Expires: time.Unix(0, 0),
		})

		// Read oauthState from Cookie
		oauthState, _ := r.Cookie("oauthstate")

		if oauthState == nil || r.FormValue("state") != oauthState.Value {
			log.Println("invalid oauth google state")
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}

		token, err := config.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in token response", http.StatusInternalServerError)
			return
		}

		// Set The JWT Token.
		http.SetCookie(w, &http.Cookie{
			Name:    "jwt",
			Value:   rawIDToken,
			// Secure:  false,
			// HttpOnly: true,
			// SameSite: http.SameSiteNoneMode,
			Expires: time.Now().Add(365 * 24 * time.Hour),
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "oauthstate",
			Expires: time.Unix(0, 0),
		})

		fmt.Fprintf(w, "UserInfo: %s\n", token)
		return
	})

	log.Println("Client is running at 5555 port.Please open http://supercomputer:5555")
	log.Fatal(http.ListenAndServe(":5555", nil))
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}