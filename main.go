package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/skratchdot/open-golang/open"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	ClientID     = ""
	ClientSecret = ""
	RedirectURL  = "http://localhost:8080/callback"
	State        = "6qK66Khnns6SMMIhsDCNUjZFubqdePmzZjiYVNV2zUIwsC6STdrI3A8qyj6E0sbQ"
)

func main() {
	config := &oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid"},
		RedirectURL:  RedirectURL,
	}

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		url := config.AuthCodeURL(State)
		fmt.Fprintf(w, url+"\n")

		open.Run(url)
	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("state") != State {
			fmt.Fprintf(w, "failed")
			return
		}

		code := r.FormValue("code")
		token, err := config.Exchange(oauth2.NoContext, code)
		if err != nil {
			fmt.Fprintf(w, "exchange error")
			return
		}

		fmt.Fprintf(w, token.AccessToken)
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
