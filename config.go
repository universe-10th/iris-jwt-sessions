package jwt_sessions

import (
	"time"
	"github.com/iris-contrib/go.uuid"
)


type (
	// Config is the configuration for sessions. Please read it before using sessions.
	Config struct {
		// Whether to reinject the new/delete the removed jwt token in the authorization
		// header again.
		AllowReclaim bool

		// The JWT session parser.
		Parser JWTParser

		// This is different with respect to cookies: expiration will be on server side,
		// if any. Client token will not expire.
		Expires time.Duration

		// SessionIDGenerator should returns a random session id.
		// By default we will use a uuid impl package to generate
		// that, but developers can change that with simple assignment.
		SessionIDGenerator func() string
	}
)


// Validate corrects missing fields configuration fields and returns the right configuration.
func (c Config) Validate() Config {
	c.Parser = c.Parser.Validate()
	if c.SessionIDGenerator == nil {
		c.SessionIDGenerator = func() string {
			id, _ := uuid.NewV4()
			return id.String()
		}
	}

	return c
}
