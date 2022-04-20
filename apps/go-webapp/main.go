package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	jwtware "github.com/gofiber/jwt/v3"
	"github.com/gofiber/template/html"

	"github.com/Nerzal/gocloak/v11"
	"github.com/golang-jwt/jwt/v4"
)

var host string = "https://localhost" // "https://penguin.linux.test"

var realm string = "master"
var clientID string = "my-resource-server"
var clientIDD string = "294bb328-cb37-4712-9269-029df5081d4d"
var clientSecret string = "FgpjFMJSEZR0tpcuFOQxmmEdunSoOHWD"

var tokenURL string = "https://localhost/realms/master/protocol/openid-connect/token"

var token *Token
var restyClient *resty.Client

func main() {

	client := gocloak.NewClient(host, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	restyClient = client.RestyClient()

	restyClient.SetDebug(false)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: false})
	ctx := context.Background()
	t, err := client.Login(ctx, clientID, clientSecret, realm, "admin", "admin")
	if err != nil {
		panic("Login failed:" + err.Error())
	}
	token = NewToken(t)
	_, err = client.GetResources(ctx, token.token.AccessToken, realm, clientIDD, gocloak.GetResourceParams{})
	if err != nil {
		panic(err)
	}

	ticker := time.NewTicker(120 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				log.Println("Refreshing token")
				t, err := client.RefreshToken(ctx, token.token.RefreshToken, clientID, clientSecret, realm)
				if err != nil {
					log.Printf("Error refreshing token: $%s", err)
				} else {
					token = NewToken(t)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	// Initialize standard Go html template engine
	engine := html.New("./views", ".html")

	app := fiber.New(fiber.Config{
		Views: engine,
	})
	app.Use(cors.New())

	app.Get("/", func(c *fiber.Ctx) error {
		// Render index template
		return c.Render("index", fiber.Map{
			"Title": "Hello, World!",
		})
	})

	jwtgroup := app.Group("/jwt", jwtware.New(jwtware.Config{
		KeySetURL:  fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", host, realm),
		ContextKey: "user",
	}))
	// jwtgroup.Use(func(c *fiber.Ctx) error {
	// 	now := epochSeconds()
	// 	log.Printf("Check token expires at: %s - %s", time.Unix(now, 0), time.Unix(token.expiresAt, 0))

	// 	if now > int64(token.expiresAt) {
	// 		log.Printf("Requesting new token with new login: %s - %d", time.Unix(now, 0), time.Unix(token.expiresAt, 0))
	// 		t, err = client.Login(ctx, clientID, clientSecret, realm, "admin", "admin")
	// 		if err != nil {
	// 			log.Println(err)
	// 			return c.Status(fiber.StatusBadRequest).SendString("Error requesting new token")
	// 		}
	// 		token = NewToken(t)
	// 	}

	// 	log.Printf("Check refresh token expires at: %s - %s", time.Unix(now, 0), time.Unix(token.refreshExpiresAt, 0))
	// 	if now-100 > int64(token.refreshExpiresAt) {
	// 		log.Printf("Requesting refresh token expires at: %s - %s", time.Unix(now, 0), time.Unix(token.refreshExpiresAt, 0))
	// 		t, err = client.RefreshToken(ctx, token.token.RefreshToken, clientID, clientSecret, realm)
	// 		if err != nil {
	// 			log.Println(err)
	// 			return c.Status(fiber.StatusBadRequest).SendString("Error requesting new token")
	// 		}
	// 		token = NewToken(t)
	// 	}
	// 	return c.Next()
	// })
	// jwtgroup.Use(func(c *fiber.Ctx) error {
	// 	user := c.Locals("user").(*jwt.Token)
	// 	perms, err := rptRequest(tokenURL, user.Raw)
	// 	if err != nil {
	// 		fmt.Printf("Error requesting resources: %s\n", err)
	// 		return c.Status(fiber.StatusUnauthorized).SendString("Error requesting RPT")
	// 	} else {
	// 		fmt.Printf("Requesting perms: %#v\n", perms)
	// 		c.Locals("rpt", &perms)
	// 	}
	// 	return c.Next()
	// })
	// jwtgroup.Use(func(c *fiber.Ctx) error {
	// 	user := c.Locals("user").(*jwt.Token)
	// 	claims := user.Claims.(jwt.MapClaims)
	// 	sub := claims["sub"].(string)
	// 	values := map[string]interface{}{"clientId": clientIDD, "userId": sub, "entitlements": false, "resources": []interface{}{
	// 		map[string]interface{}{"type": "org"},
	// 	}}

	// 	jsonValue, _ := json.Marshal(values)
	// 	resp, err := restyClient.R().SetAuthToken(token.token.AccessToken).SetBody(bytes.NewBuffer(jsonValue)).SetHeader("Accept", "application/json").Post("https://localhost/admin/realms/master/clients/294bb328-cb37-4712-9269-029df5081d4d/authz/resource-server/policy/evaluate")
	// 	if err != nil {
	// 		log.Println(err)
	// 		return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
	// 	}

	// 	var ev Evaluate
	// 	err = json.Unmarshal(resp.Body(), &ev)
	// 	if err != nil {
	// 		log.Println(err)
	// 		return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
	// 	}
	// 	c.Locals("ev", &ev)
	// 	return c.Next()
	// })
	// Write File
	// jwtgroup.Use(func(c *fiber.Ctx) error {
	// 	ev := c.Locals("ev").(*Evaluate)
	// 	if ev == nil {
	// 		return c.Next()
	// 	}
	// 	bev, err := json.Marshal(ev)
	// 	if err != nil {
	// 		return c.Next()
	// 	}
	// 	b, err := prettyprint(bev)
	// 	if err != nil {
	// 		return c.Next()
	// 	}
	// 	f, err := os.Create("data.json")
	// 	if err != nil {
	// 		return c.Next()
	// 	}
	// 	defer f.Close()
	// 	_, err = f.WriteString(string(b))
	// 	if err != nil {
	// 		return c.Next()
	// 	}
	// 	fmt.Println("file written done")
	// 	return c.Next()
	// })
	jwtgroup.Get("/", func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		email := claims["email"].(string)
		s := fmt.Sprintf("Hello, OIDC 👋! --- %s ", email)
		return c.SendString(s)
	})
	jwtgroup.Get("/orgs", func(c *fiber.Ctx) error {
		user := c.Locals("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		sub := claims["sub"].(string)
		values := map[string]interface{}{"clientId": clientIDD, "userId": sub, "entitlements": false, "resources": []interface{}{
			map[string]interface{}{"type": "org"},
		}}

		jsonValue, _ := json.Marshal(values)
		resp, err := restyClient.R().SetAuthToken(token.token.AccessToken).SetBody(bytes.NewBuffer(jsonValue)).SetHeader("Accept", "application/json").Post("https://localhost/admin/realms/master/clients/294bb328-cb37-4712-9269-029df5081d4d/authz/resource-server/policy/evaluate")
		if err != nil {
			log.Println(err)
			return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		}

		var ev Evaluate
		err = json.Unmarshal(resp.Body(), &ev)
		if err != nil {
			log.Println(err)
			return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		}
		fmt.Printf("Evaluate Permissions: %#v\n", ev.Rpt.Authorization.Permissions)
		for _, p := range ev.Rpt.Authorization.Permissions {
			fmt.Printf("Permssion: %s\n", p.Rsname)
			fmt.Printf("Permssion: %s\n", p.Scopes)
			fmt.Println("----")
		}
		return c.JSON(ev.Rpt.Authorization.Permissions)
	})

	jwtgroup.Get("/orgs/:org", func(c *fiber.Ctx) error {
		orgID := c.Params("org")
		user := c.Locals("user").(*jwt.Token)
		claims := user.Claims.(jwt.MapClaims)
		sub := claims["sub"].(string)
		// values := map[string]interface{}{"clientId": clientIDD, "userId": sub, "entitlements": false, "resources": []interface{}{
		// 	map[string]interface{}{"type": "team"},
		// }}

		// jsonValue, _ := json.Marshal(values)
		// resp, err := restyClient.R().SetAuthToken(token.token.AccessToken).SetBody(bytes.NewBuffer(jsonValue)).SetHeader("Accept", "application/json").Post("https://localhost/admin/realms/master/clients/294bb328-cb37-4712-9269-029df5081d4d/authz/resource-server/policy/evaluate")
		// if err != nil {
		// 	log.Println(err)
		// 	return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		// }

		// var ev Evaluate
		// err = json.Unmarshal(resp.Body(), &ev)
		// if err != nil {
		// 	log.Println(err)
		// 	return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		// }

		// ch := make(chan Evaluate)
		// che := make(chan error)
		// go getPolicyEvaluation("team", sub, ch, che)
		// ev := <-ch
		// err := <-che
		// if err != nil {
		// 	log.Println(err)
		// 	return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		// }
		// var ev Evaluate
		// for {
		// 	select {
		// 	case ev = <-ch:
		// 		fmt.Println("Receiving channel evaluation")
		// 		perms := []Permission{}
		// 		for _, p := range ev.Rpt.Authorization.Permissions {
		// 			// Delete all team resources which hve not the name ":org" in it's name
		// 			log.Printf("Org name: %s", orgID)
		// 			log.Printf("Resource name: %s", p.Rsname)
		// 			if strings.Contains(p.Rsname, orgID) {
		// 				perms = append(perms, p)
		// 			}
		// 		}

		// 		return c.JSON(perms)
		// 	case err := <-che:
		// 		log.Println(err)
		// 		return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		// 	}
		// }

		ev, err := getPolicyEvaluation("team", sub)
		if err != nil {
			log.Println(err)
			return c.Status(fiber.StatusBadRequest).SendString("Error requesting evaluation")
		}

		perms := []Permission{}
		for _, p := range ev.Rpt.Authorization.Permissions {
			// Delete all team resources which hve not the name ":org" in it's name
			log.Printf("Org name: %s", orgID)
			log.Printf("Resource name: %s", p.Rsname)
			if strings.Contains(p.Rsname, orgID) {
				perms = append(perms, p)
			}
		}

		return c.JSON(perms)

	})

	app.ListenTLS(":3001", "./../../certs/wsl/localhost+2.pem", "./../../certs/wsl/localhost+2-key.pem")
	// log.Fatal(http.ListenAndServeTLS(":3000", "./../../certs/wsl/localhost+2.pem", "./../../certs/wsl/localhost+2-key.pem", nil))
}

func getPolicyEvaluation(t string, sub string) (*Evaluate, error) {
	var ev Evaluate
	values := map[string]interface{}{"clientId": clientIDD, "userId": sub, "entitlements": false, "resources": []interface{}{
		map[string]interface{}{"type": t},
	}}
	jsonValue, _ := json.Marshal(values)
	resp, err := restyClient.R().SetAuthToken(token.token.AccessToken).SetBody(bytes.NewBuffer(jsonValue)).SetHeader("Accept", "application/json").Post("https://localhost/admin/realms/master/clients/294bb328-cb37-4712-9269-029df5081d4d/authz/resource-server/policy/evaluate")
	if err != nil {
		return &ev, err
	}

	err = json.Unmarshal(resp.Body(), &ev)
	if err != nil {
		return &ev, err
	}
	fmt.Println("Request evauation policy succesfull")
	return &ev, nil
}

func getPolicyEvaluationAsync(t string, sub string, ch chan<- Evaluate, che chan<- error) {
	values := map[string]interface{}{"clientId": clientIDD, "userId": sub, "entitlements": false, "resources": []interface{}{
		map[string]interface{}{"type": t},
	}}
	jsonValue, _ := json.Marshal(values)
	resp, err := restyClient.R().SetAuthToken(token.token.AccessToken).SetBody(bytes.NewBuffer(jsonValue)).SetHeader("Accept", "application/json").Post("https://localhost/admin/realms/master/clients/294bb328-cb37-4712-9269-029df5081d4d/authz/resource-server/policy/evaluate")
	if err != nil {
		che <- err
	}
	var ev Evaluate
	err = json.Unmarshal(resp.Body(), &ev)
	if err != nil {
		che <- err
	}
	fmt.Println("Request evauation policy succesfull")
	ch <- ev
}

//dont do this, see above edit
func prettyprint(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "  ")
	return out.Bytes(), err
}
