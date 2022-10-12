package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/bndr/gotabulate"
	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

var (
	clientID     string
	clientSecret string
	userID       string

	authServerURL string
)

func init() {

	flag.StringVar(&clientID, "i", "", "client id")

	flag.StringVar(&clientSecret, "s", "", "client secret")

	flag.StringVar(&userID, "u", "", "user id")

	flag.StringVar(&authServerURL, "auth-url", "", "client serve port")

	flag.Usage = usage

	flag.Parse()

	if len(clientID) == 0 {
		panic("client id is empty")
	}

	if len(clientSecret) == 0 {
		panic("client secret is empty")
	}

	if len(userID) == 0 {
		panic("user id is empty")
	}

	if len(authServerURL) == 0 {
		panic("auth server url is empty")
	}
}

// 印出預設的說明
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: oa2cli [options] \n")
	fmt.Fprintf(os.Stderr, "  Currently, the following flags can be used\n")
	flag.PrintDefaults()
}

const ()

var (
	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authServerURL + "/v1/oauth/authorize",
			TokenURL:  authServerURL + "/v1/oauth/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	globalToken *oauth2.Token // Non-concurrent security
)

func main() {

	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		u := config.AuthCodeURL("xyz",
			oauth2.SetAuthURLParam("code_challenge", genCodeChallengeS256("s256example")),
			oauth2.SetAuthURLParam("user_id", userID),
		)
		http.Redirect(c.Response().Writer, c.Request(), u, http.StatusFound)

		return nil
	})

	e.GET("/oauth", func(c echo.Context) error {

		state := c.Request().Form.Get("state")
		if state != "xyz" {
			http.Error(c.Response().Writer, "State invalid", http.StatusBadRequest)
			return nil
		}
		code := c.Request().Form.Get("code")
		if code == "" {
			http.Error(c.Response().Writer, "Code not found", http.StatusBadRequest)
			return nil
		}

		token, err := config.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", "s256example"))
		if err != nil {
			http.Error(c.Response().Writer, err.Error(), http.StatusInternalServerError)
			return nil
		}

		globalToken = token

		prettyPrintToken(globalToken)

		c.Response().Write([]byte("OK"))

		return nil
	})

	e.GET("/refresh", func(c echo.Context) error {

		w := c.Response().Writer
		r := c.Request()

		if globalToken == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return nil
		}

		globalToken.Expiry = time.Now()
		token, err := config.TokenSource(context.Background(), globalToken).Token()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}

		globalToken = token

		prettyPrintToken(globalToken)

		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(token)

		return nil
	})

	e.GET("/account", func(c echo.Context) error {
		w := c.Response().Writer
		r := c.Request()

		if globalToken == nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return nil
		}
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/oauth/exchange/account", authServerURL), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}

		req.Header.Set("Authorization", "Bearer "+globalToken.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return nil
		}
		defer resp.Body.Close()

		io.Copy(w, resp.Body)
		return nil
	})

	// log.Printf("Client is running at %s port.Please open http://localhost:%s", port, port)
	log.Fatal(e.Start(":" + os.Getenv("PORT")))
}

func genCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}

func prettyPrintToken(token *oauth2.Token) {

	// Some Strings
	string_1 := []string{globalToken.AccessToken, globalToken.RefreshToken, globalToken.Expiry.String(), globalToken.TokenType}

	// Create Object
	tabulate := gotabulate.Create([][]string{string_1})

	// Set Headers
	tabulate.SetHeaders([]string{"Access Token", "Refresh Token", "Expiry", "Token Type"})

	// Render
	fmt.Println(tabulate.Render("simple"))
}
