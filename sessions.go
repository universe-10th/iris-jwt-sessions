package jwt_sessions

import (
	"time"
	"github.com/kataras/iris/sessions"
	"github.com/kataras/iris/context"
	"github.com/dgrijalva/jwt-go"
	"github.com/kataras/iris"
	"strings"
	"fmt"
)

// JWT sessions work mostly like normal sessions, but against a
// context-parsed JWT instead of against a cookie. Aside from that,
// they should be understood/used pretty much like regular sessions.
// (Note to myself: hopefully I can take a lot of code from the
// regular Iris sessions).
type JWTSessions struct {
	config   Config
	provider *provider
}


// New returns a new fast, feature-rich sessions manager
// it can be adapted to an iris station
func New(cfg Config) *JWTSessions {
	return &JWTSessions{
		config:   cfg.Validate(),
		provider: newProvider(),
	}
}

// UseDatabase adds a session database to the manager's provider,
// a session db doesn't have write access
func (sessions *JWTSessions) UseDatabase(db sessions.Database) {
	sessions.provider.RegisterDatabase(db)
}

// updateJWT gains the ability of updating the session browser cookie to any method which wants to update it
func (sessions *JWTSessions) updateJWT(ctx context.Context, sessionID string, expires time.Duration) {
	token := jwt.NewWithClaims(sessions.config.Parser.SigningMethod, jwt.MapClaims{
		"session_id": sessionID,
	})

	if (sessions.config.AllowReclaim) {
		serialized, _ := sessions.config.Parser.Serialize(token)
		if serialized != "" {
			if sessions.config.AllowReclaim {
				ctx.Request().Header.Set("Authorization", "Bearer " + serialized)
			}
			ctx.Header("Authorization", "Bearer" + serialized)
		}
	}
}

// Extracts the token from an "Authorization: bearer <token>"
// header (extracts and returns the encoded string).
func (sessions *JWTSessions) readJWT(ctx iris.Context) (string, error) {
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Split(authHeader, " ")
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", fmt.Errorf("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

func (sessions *JWTSessions) sessionIDFromContext(ctx context.Context) string {
	tokenString, _ := sessions.readJWT(ctx)
	if tokenString == "" {
		return ""
	}

	token, _ := sessions.config.Parser.Parse(tokenString)
	sessionID := ""
	if token != nil {
		claims, _ := token.Claims.(jwt.MapClaims)
		sessionID, _ = claims["session_id"].(string)
	}
	return sessionID
}

// Start should start the session for the particular request.
func (sessions *JWTSessions) Start(ctx context.Context) *JWTSession {
	sessionID := sessions.sessionIDFromContext(ctx)
	if sessionID == "" {
		sessionID := sessions.config.SessionIDGenerator()
		sess := sessions.provider.Init(sessionID, sessions.config.Expires)
		sess.isNew = sessions.provider.db.Len(sessionID) == 0
		sessions.updateJWT(ctx, sessionID, sessions.config.Expires)
		return sess
	} else {
		return sessions.provider.Read(sessionID, sessions.config.Expires)
	}
}

// ShiftExpiration move the expire date of a session to a new date
// by using session default timeout configuration.
// It will return `ErrNotImplemented` if a database is used and it does not support this feature, yet.
func (sessions *JWTSessions) ShiftExpiration(ctx context.Context) error {
	return sessions.UpdateExpiration(ctx, sessions.config.Expires)
}

// UpdateExpiration change expire date of a session to a new date
// by using timeout value passed by `expires` receiver.
// It will return `ErrNotFound` when trying to update expiration on a non-existence or not valid session entry.
// It will return `ErrNotImplemented` if a database is used and it does not support this feature, yet.
func (sessions *JWTSessions) UpdateExpiration(ctx context.Context, expires time.Duration) error {
	sessionID := sessions.sessionIDFromContext(ctx)
	if sessionID == "" {
		return ErrNotFound
	} else {
		return sessions.provider.UpdateExpiration(sessionID, expires)
	}
}

// OnDestroy registers one or more destroy listeners.
// A destroy listener is fired when a session has been removed entirely from the server (the entry) and client-side (the cookie).
// Note that if a destroy listener is blocking, then the session manager will delay respectfully,
// use a goroutine inside the listener to avoid that behavior.
func (sessions *JWTSessions) OnDestroy(listeners ...sessions.DestroyListener) {
	for _, ln := range listeners {
		sessions.provider.registerDestroyListener(ln)
	}
}

// Destroy removes the session data by context.
func (sessions *JWTSessions) Destroy(ctx context.Context) {
	sessionID := sessions.sessionIDFromContext(ctx)
	if sessionID != "" {
		sessions.DestroyByID(sessionID)
	}
	if sessions.config.AllowReclaim {
		ctx.Request().Header.Del("Authorization")
	}
}

// DestroyByID removes the session data by ID.
func (sessions *JWTSessions) DestroyByID(sid string) {
	sessions.provider.Destroy(sid)
}

// DestroyAll removes all sessions.
func (sessions *JWTSessions) DestroyAll() {
	sessions.provider.DestroyAll()
}

