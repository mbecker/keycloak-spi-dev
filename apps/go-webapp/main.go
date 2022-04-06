package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
	"github.com/mbecker/go-webapp/oidchandler"
	"golang.org/x/oauth2"
)

var configURL string = "https://localhost/realms/master"
var issuerURL string = "https://localhost/realms/master"
var penguinIssuerURL string = "https://penguin.linux.test/realms/master"
var clientID string = "my-resource-server"
var clientSecret string = "CsraCM20RwbcHF8SJmenGA930hgblub8"
var redirectURL string = "https://localhost:3000/demo/callback"
var penguinredirectURL string = "http://penguin.linux.test:3000/demo/callback"
var state string = "somestate"

func main() {
	// Initialize standard Go html template engine
	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	app.Get("/", func(c *fiber.Ctx) error {
		// Render index template
		return c.Render("index", fiber.Map{
			"Title": "Hello, World!",
		})
	})

	oidc := app.Group("/oidc", oidchandler.New(oidchandler.Config{
		ContextKey: "test",
	}))

	oidc.Get("/", func(c *fiber.Ctx) error {
		s := fmt.Sprintf("Hello, OIDC 👋! --- %s ", c.Locals("test"))
		return c.SendString(s)
	})

	app.ListenTLS(":3000", "./../../certs/wsl/localhost+2.pem", "./../../certs/wsl/localhost+2-key.pem")
	// log.Fatal(http.ListenAndServeTLS(":3000", "./../../certs/wsl/localhost+2.pem", "./../../certs/wsl/localhost+2-key.pem", nil))
}

func test() {

	parentContext := context.Background()
	ctx := oidc.InsecureIssuerURLContext(parentContext, issuerURL)

	// Provider will be discovered with the discoveryBaseURL, but use issuerURL
	// for future issuer validation.

	provider, err := oidc.NewProvider(ctx, configURL)
	if err != nil {
		panic(err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rawAccessToken := r.Header.Get("Authorization")
		if rawAccessToken == "" {
			log.Printf("Login redirect: %s\n", oauth2Config.AuthCodeURL(state))
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		parts := strings.Split(rawAccessToken, " ")
		if len(parts) != 2 {
			w.WriteHeader(400)
			return
		}
		_, err := verifier.Verify(ctx, parts[1])

		if err != nil {
			http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
			return
		}

		w.Write([]byte("hello world"))
	})

	http.HandleFunc("/demo/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token   *oauth2.Token
			IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
		}{oauth2Token, new(json.RawMessage)}

		if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Fatal(http.ListenAndServeTLS(":3000", "./../../certs/wsl/localhost+2.pem", "./../../certs/wsl/localhost+2-key.pem", nil))

	// app := fiber.New()

	// app.Get("/", func(c *fiber.Ctx) error {
	// 	return c.SendString("Hello, World 👋!")
	// })

	// app.Listen(":3000")
}
