package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"

	gocloak "github.com/Nerzal/gocloak/v11"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
)

var URL string = "https://127.0.0.1:8443"

type Resource struct {
	Scopes []string `json:"scopes"`
	Rsid   string   `json:"rsid"`
	Rsname string   `json:"rsname"`
}

var realm string = "master"
var clientID string = "my-resource-server"
var clientSecret string = "DfTpWwh8wbqgOjECIfYUxFbpaeNUg4MQ"

// grant_type := "password"
var mbecker string = "mats.becker@gmail.com"
var mefobe string = "mefobe@gmail.com"
var password string = "sack77"

// response_type := "token"

var idmatsbecker string = "b88e1066-d0b8-488e-887e-3130c140a6d9"

func main() {

	// createResourceClient()
	// clientResources()
	userResources(mefobe, password)

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

	log.Fatal(app.Listen(":3000"))
}

func userResources(u, p string) {
	client := gocloak.NewClient(URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	restyClient := client.RestyClient()
	restyClient.SetDebug(true)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ctx := context.Background()
	token, err := client.Login(ctx, clientID, clientSecret, realm, u, p)
	if err != nil {
		panic("Login failed:" + err.Error())
	}
	fmt.Println(token)

	// resources, err := client.GetResourcesClient(ctx, token.AccessToken, realm, gocloak.GetResourceParams{
	// 	Type: gocloak.StringP("org"),
	// })
	// if err != nil {
	// 	panic("Resources failed:" + err.Error())
	// }
	// fmt.Println(resources)

	rptResult, err := client.RetrospectToken(ctx, token.AccessToken, clientID, clientSecret, realm)
	if err != nil {
		panic("Inspection failed:" + err.Error())
	}

	if !*rptResult.Active {
		panic("Token is not active")
	}

	permissions := rptResult.Permissions
	fmt.Printf("Permissions: %#v", permissions)
	return

	resp, err := restyClient.R().SetAuthToken(token.AccessToken).SetFormData(map[string]string{
		"grant_type":                     "urn:ietf:params:oauth:grant-type:",
		"permission":                     "org:*#GET",
		"alias":                          "org",
		"audience":                       clientID,
		"response_mode":                  "permissions",
		"response_include_resource_name": "true",
	}).SetHeader("Accept", "application/json").Post("https://localhost:8443/realms/master/protocol/openid-connect/token")
	if err != nil {
		panic("Resources failed:" + err.Error())
	}
	fmt.Println(resp)
	// var reosurces []Resource
	// err = json.Unmarshal(resp.Body(), &reosurces)
	// if err != nil {
	// 	panic("Resources unmarshal failed:" + err.Error())
	// }
	// fmt.Printf("%#v", reosurces)
}

func clientResources() {
	client := gocloak.NewClient(URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	restyClient := client.RestyClient()
	restyClient.SetDebug(true)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ctx := context.Background()
	token, err := client.LoginClient(ctx, clientID, clientSecret, realm)
	handleError("Client Resources Login", err)

	resources, err := client.GetResources(ctx, token.AccessToken, realm, clientID, gocloak.GetResourceParams{
		Type: gocloak.StringP("team"),
	})
	// client.GetResourcesClient(ctx, token.AccessToken, realm, gocloak.GetResourceParams{
	// Type: gocloak.StringP("team"),
	// })
	handleError("Client Resources Get Resources", err)
	fmt.Printf("%#v", resources)
}

func createResourceClient() {
	client := gocloak.NewClient(URL, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	restyClient := client.RestyClient()
	restyClient.SetDebug(true)
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	ctx := context.Background()
	token, err := client.LoginClient(ctx, clientID, clientSecret, realm)
	handleError("Create Resource Client - Login Client: ", err)

	// Create Resource
	var resourceName string = "workspace1"
	resourceRepresentation := gocloak.ResourceRepresentation{
		ID:          &resourceName,
		DisplayName: &resourceName,
		Name:        &resourceName,
		Owner: &gocloak.ResourceOwnerRepresentation{
			ID:   &idmatsbecker,
			Name: &mbecker,
		},
		OwnerManagedAccess: gocloak.BoolP(true),
		Scopes: &[]gocloak.ScopeRepresentation{
			{
				Name: gocloak.StringP("PUT"),
			},
			{
				Name: gocloak.StringP("PATCH"),
			},
			{
				Name: gocloak.StringP("DELETE"),
			},
			{
				Name: gocloak.StringP("GET"),
			},
			{
				Name: gocloak.StringP("POST"),
			},
		},
		Type: gocloak.StringP("workspace"),
		URIs: &[]string{"/workspace1", "/workspace1/*"},
	}

	resource, err := client.CreateResourceClient(ctx, token.AccessToken, realm, resourceRepresentation)
	handleError("Create Resource Client - Create Resource Client: ", err)
	log.Printf("Resource: %#v", resource)
}

func handleError(msg string, err error) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}
