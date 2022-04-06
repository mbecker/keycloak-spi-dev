package oidchandler

import (
	"github.com/gofiber/fiber/v2"
)

// Config defines the config for JWT middleware
type Config struct {
	// SuccessHandler defines a function which is executed for a valid token.
	// Optional. Default: nil
	SuccessHandler fiber.Handler
	// Context key to store user information from the token into context.
	// Optional. Default: "user".
	ContextKey string
}

// New ...
func New(config ...Config) fiber.Handler {
	cfg := makeCfg(config)
	// Return middleware handler
	return func(c *fiber.Ctx) error {
		if cfg.ContextKey != "" {
			c.Locals(cfg.ContextKey, "TEST TEST TEST")
			return cfg.SuccessHandler(c)
		}
		return c.Next()
	}
}

// makeCfg function will check correctness of supplied configuration
// and will complement it with default values instead of missing ones
func makeCfg(config []Config) (cfg Config) {
	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) error {
			return c.Next()
		}
	}
	if cfg.ContextKey == "" {
		cfg.ContextKey = "user"
	}
	return cfg
}
