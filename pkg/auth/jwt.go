package auth

import (
	"crypto/rsa"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Auth struct represents parsed jwt information.
type Auth struct {
	UID        string      `json:"uid"`
	Email      string      `json:"email"`
	Role       string      `json:"role"`
	jwt.StandardClaims
}

// ParseAndValidate parses token and validates it's jwt signature with given key.
func ParseAndValidate(token string, key *rsa.PublicKey) (Auth, error) {
	auth := Auth{}

	_, err := jwt.ParseWithClaims(token, &auth, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})

	return auth, err
}

func appendClaims(defaultClaims, customClaims jwt.MapClaims) jwt.MapClaims {
	if defaultClaims == nil {
		return customClaims
	}

	if customClaims == nil {
		return defaultClaims
	}

	for k, v := range customClaims {
		defaultClaims[k] = v
	}

	return defaultClaims
}

// ForgeToken creates a valid JWT signed by the given private key
func ForgeToken(uid, email, role string, level int, key *rsa.PrivateKey, customClaims jwt.MapClaims) (string, error) {
	claims := appendClaims(jwt.MapClaims{
		"iat":         time.Now().Unix(),
		"jti":         strconv.FormatInt(time.Now().Unix(), 10),
		"exp":         time.Now().UTC().Add(time.Hour).Unix(),
		"iss":         "beautycare",
		"uid":         uid,
		"email":       email,
		"role":        role,
	}, customClaims)

	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return t.SignedString(key)
}
