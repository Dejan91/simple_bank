package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

// CustomClaims contains the payload data of the token and jwt registered claims
type CustomClaims struct {
	Username string
	jwt.RegisteredClaims
}

// NewClaims creates a new custom claims
func NewClaims(username string, duration time.Duration) (*CustomClaims, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	claims := &CustomClaims{
		username,
		jwt.RegisteredClaims{
			// A usual scenario is to set the expiration time relative to the current time
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "",
			Subject:   "",
			ID:        tokenID.String(),
			Audience:  []string{},
		},
	}

	return claims, err
}
