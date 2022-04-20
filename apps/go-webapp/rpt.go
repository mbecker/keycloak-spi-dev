package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

func rptRequest(keycloakURL string, token string) (Permissions, error) {

	var perm Permissions
	var keycloakError KeycloakError
	var httpError HTTPError
	method := "POST"
	payload := strings.NewReader("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket&audience=my-resource-server&response_mode=permissions")

	client := &http.Client{}
	req, err := http.NewRequest(method, keycloakURL, payload)

	if err != nil {
		log.Printf("HTTP Request Error: %v\n", err)
		httpError = HTTPError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("HTTP Request Error: %s", err.Error()),
		}
		return perm, &httpError
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		log.Printf("HTTP Response Error: %v\n", err)
		httpError = HTTPError{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("HTTP Response Error: %s", err.Error()),
		}
		return perm, &httpError
	}
	defer res.Body.Close()

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal(bodyBytes, &keycloakError)
	if err == nil {
		log.Printf("Auth Error: %v\n", err)
		httpError = HTTPError{
			StatusCode: res.StatusCode,
			Message:    fmt.Sprintf("Auth Error: %s - %s", keycloakError.Error, keycloakError.ErrorDescription),
		}
		return perm, &httpError
	}

	err = json.Unmarshal(bodyBytes, &perm)
	if err != nil {
		httpError = HTTPError{
			StatusCode: http.StatusInternalServerError,
			Message:    err.Error(),
		}
		return perm, &httpError
	}

	for i, _ := range perm {
		perm[i].MScopes = map[string]bool{}
		for _, scope := range perm[i].Scopes {
			perm[i].MScopes[scope] = true
		}
		// Get Type of resource
		if strings.Contains(perm[i].Rsname, ":team:") {
			perm[i].Type = "team"
		} else if strings.Contains(perm[i].Rsname, "org:") {
			perm[i].Type = "org"
		}
	}
	return perm, nil
}
