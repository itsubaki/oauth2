package main

import (
	"fmt"

	v2 "google.golang.org/api/oauth2/v2"

	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	ClientID     = ""
	ClientSecret = ""
	RedirectURL  = "http://localhost:8080/callback"
)

var config = &oauth2.Config{
	ClientID:     ClientID,
	ClientSecret: ClientSecret,
	Endpoint:     google.Endpoint,
	Scopes:       []string{"openid", "email", "profile"},
	RedirectURL:  RedirectURL,
}

func main() {
	g := gin.Default()
	g.GET("/login", func(c *gin.Context) {
		state := uuid.NewV4().String()
		url := config.AuthCodeURL(state)
		c.SetCookie("state", state, 360, "/", "", false, true)
		c.Redirect(302, url)
	})

	g.GET("/callback", func(c *gin.Context) {
		cookie, err := c.Cookie("state")
		if err != nil {
			c.JSON(401, fmt.Sprintf("cookie not found: %v", err))
			return
		}

		state := c.Query("state")
		if cookie != state {
			c.JSON(401, "state is invalid")
			return
		}

		code := c.Query("code")
		token, err := config.Exchange(oauth2.NoContext, code)
		if err != nil {
			c.JSON(401, fmt.Sprintf("exchange=%s: %v", code, err))
			return
		}

		if !token.Valid() {
			c.JSON(401, "token is invalid")
			return
		}

		service, err := v2.New(config.Client(oauth2.NoContext, token))
		if err != nil {
			c.JSON(401, fmt.Sprintf("client new: %v", err))
			return
		}

		if _, err := service.Tokeninfo().AccessToken(token.AccessToken).Context(oauth2.NoContext).Do(); err != nil {
			c.JSON(401, fmt.Sprintf("token info: %v", err))
			return
		}

		c.JSON(200, token)
	})

	g.Run(":8080")
}
