package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"google.golang.org/api/option"

	v2 "google.golang.org/api/oauth2/v2"

	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func New() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid", "email", "profile"},
	}
}

func main() {
	config := New()
	fmt.Printf("%#v\n", config)

	g := gin.Default()
	g.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, c.Request.Header)
	})

	g.GET("/login", func(c *gin.Context) {
		state := uuid.NewV4().String()
		url := config.AuthCodeURL(state)
		c.SetCookie("state", state, 360, "/", "", false, true)
		c.Redirect(http.StatusFound, url)
	})

	g.GET("/callback", func(c *gin.Context) {
		cookie, err := c.Cookie("state")
		if err != nil {
			c.JSON(http.StatusUnauthorized, fmt.Sprintf("cookie not found: %v", err))
			return
		}

		state := c.Query("state")
		if cookie != state {
			c.JSON(http.StatusUnauthorized, "state is invalid")
			return
		}

		ctx := context.Background()
		code := c.Query("code")
		token, err := config.Exchange(ctx, code)
		if err != nil {
			c.JSON(http.StatusUnauthorized, fmt.Sprintf("exchange=%s: %v", code, err))
			return
		}

		if !token.Valid() {
			c.JSON(http.StatusUnauthorized, "token is invalid")
			return
		}

		service, err := v2.NewService(ctx, option.WithTokenSource(config.TokenSource(ctx, token)))
		if err != nil {
			c.JSON(http.StatusUnauthorized, fmt.Sprintf("client new: %v", err))
			return
		}

		info, err := service.Tokeninfo().AccessToken(token.AccessToken).Context(context.Background()).Do()
		if err != nil {
			c.JSON(http.StatusUnauthorized, fmt.Sprintf("token info: %v", err))
			return
		}

		c.JSON(http.StatusOK, info)
	})

	g.Run(":8080")
}
