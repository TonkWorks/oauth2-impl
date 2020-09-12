package main

import (
	"log"
	"net/http"
	"fmt"

	"github.com/spf13/viper"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
)


func main() {
	
	// Config
	viper.AutomaticEnv()
	viper.SetConfigName("conf") // name of config file (without extension)
	viper.AddConfigPath(".")               // optionally look for config in the working directory
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	//Oauth2
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	id := viper.GetString("id")
	secret := viper.GetString("secret")
	domain :=  viper.GetString("domain")

	clientStore := store.NewClientStore()
	clientStore.Set(id, &models.Client{
		ID:     id,
		Secret: secret,
		Domain: domain,
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		srv.HandleTokenRequest(w, r)
	})

	log.Fatal(http.ListenAndServe(":8000", nil))
}
