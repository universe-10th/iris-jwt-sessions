package jwt_sessions

import (
	"github.com/dgrijalva/jwt-go"
	"strings"
	"fmt"
	"github.com/kataras/iris"
	"time"
)


type JWTContextParser struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// When set, all requests with the OPTIONS method will use authentication
	// if you enable this option you should register your route with iris.Options(...) also
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
	// When set, the expiration time of token will be check every time
	// if the token was expired, expiration error will be returned
	// Default: false
	Expiration bool
}


// Extracts the token from an "Authorization: bearer <token>"
// header (extracts and returns the encoded string).
func fromAuthHeader(ctx iris.Context) (string, error) {
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


// Parses a JWT token from a context.
func (jwtContextParser *JWTContextParser) Parse(ctx iris.Context) (*jwt.Token, error) {
	// Calls (or not) also this token-fetching
	// if in an "OPTIONS"-method context.
	if !jwtContextParser.EnableAuthOnOptions {
		if ctx.Method() == iris.MethodOptions {
			return nil, nil
		}
	}

	// Extracts the token, and catch any error.
	if token, err := fromAuthHeader(ctx); err != nil {
		return nil, fmt.Errorf("error extracting token: %v", err)
	} else if token == "" {
		return nil, nil
	} else {
		if parsedToken, err := jwt.Parse(token, jwtContextParser.ValidationKeyGetter); err != nil {
			return nil, fmt.Errorf("error parsing token: %v", err)
		} else {
			// Check if the signing algorithm is the one we use.
			if jwtContextParser.SigningMethod != nil && jwtContextParser.SigningMethod.Alg() != parsedToken.Header["alg"] {
				message := fmt.Sprintf(
					"Expected %s signing method but token specified %s",
					jwtContextParser.SigningMethod.Alg(),
					parsedToken.Header["alg"],
                )
				return nil, fmt.Errorf("error validating token algorithm: %s", message)
			}

			// Then check if the token is valid...
			if !parsedToken.Valid {
				return nil, fmt.Errorf("token is invalid")
			}

			// ...and if the token is expired.
			if jwtContextParser.Expiration {
				if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
					if expired := claims.VerifyExpiresAt(time.Now().Unix(), true); !expired {
						return nil, fmt.Errorf("token is expired")
					}
				}
			}

			// Finally return the token.
			return parsedToken, nil
		}
	}
}
