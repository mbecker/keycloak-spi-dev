package main

import (
	"fmt"
	"time"

	"github.com/Nerzal/gocloak/v11"
)

func epochSeconds() int64 {
	now := time.Now()
	secs := now.Unix()
	return secs
}

type Token struct {
	token            *gocloak.JWT
	expiresAt        int64
	refreshExpiresAt int64
	now              int64
}

func NewToken(token *gocloak.JWT) *Token {
	secs := epochSeconds()
	t := Token{
		token:            token,
		now:              secs,
		expiresAt:        secs + int64(token.ExpiresIn),
		refreshExpiresAt: secs + int64(token.RefreshExpiresIn),
	}
	return &t
}

type Evaluate struct {
	Rpt struct {
		Authorization struct {
			Permissions []Permission `json:"permissions"`
		} `json:"authorization"`
	} `json:"rpt"`
}

// Permissions represent the returned permissions from Keycloak RPT
type Permissions []Permission

type Permission struct {
	Scopes  []string        `json:"scopes,omitempty"`
	MScopes map[string]bool `json:"mscopes,omitempty"`
	Rsid    string          `json:"rsid"`
	Rsname  string          `json:"rsname"`
	Type    string          `json:"type"`
}

type KeycloakError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type HTTPError struct {
	StatusCode int    `json:"statuscode"`
	Message    string `json:"message"`
}

func NewHTTPError(statusCode int, message string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
	}
}

func (h *HTTPError) Error() string {
	return fmt.Sprintf("HTTP Error %d: %s", h.StatusCode, h.Message)
}
