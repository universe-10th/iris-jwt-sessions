package jwt_sessions

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)


type JWTParser struct {
	// The bidirectional secret to sign/validate a token.
	Secret interface{}
	// The function that will return the Key to sign the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	SigningKeyGetter jwt.Keyfunc
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
}


// Parses a JWT token from a context.
func (jwtParser *JWTParser) Parse(token string) (*jwt.Token, error) {
	// Extracts the token, and catch any error.
	if token == "" {
		return nil, nil
	} else {
		if parsedToken, err := jwt.ParseWithClaims(token, jwt.MapClaims{}, jwtParser.ValidationKeyGetter); err != nil {
			return nil, fmt.Errorf("error parsing token: %v", err)
		} else {
			// Check if the signing algorithm is the one we use.
			if jwtParser.SigningMethod != nil && jwtParser.SigningMethod.Alg() != parsedToken.Header["alg"] {
				message := fmt.Sprintf(
					"Expected %s signing method but token specified %s",
					jwtParser.SigningMethod.Alg(),
					parsedToken.Header["alg"],
                )
				return nil, fmt.Errorf("error validating token algorithm: %s", message)
			}

			// Then check if the token is valid.
			if !parsedToken.Valid {
				return nil, fmt.Errorf("token is invalid")
			}

			// Finally return the token.
			return parsedToken, nil
		}
	}
}


// Serializes a key
func (jwtParser *JWTParser) Serialize(token *jwt.Token) (string, error) {
	if key, err := jwtParser.SigningKeyGetter(token); err != nil || key == nil {
		return "", err
	} else {
		return token.SignedString(key)
	}
}


// Validates the parser (adds default key functions if not given) - returns a copy.
func (jwtParser JWTParser) Validate() JWTParser {
	if jwtParser.SigningKeyGetter == nil {
		jwtParser.SigningKeyGetter = func(*jwt.Token) (interface{}, error) {
			return jwtParser.Secret, nil
		}
	}
	if jwtParser.ValidationKeyGetter == nil {
		jwtParser.ValidationKeyGetter = func(*jwt.Token) (interface{}, error) {
			return jwtParser.Secret, nil
		}
	}
	return jwtParser
}