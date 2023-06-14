package token

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

const minSecretKeySize = 32

// JWTMaker is a JSON Web Token maker
type JWTMaker struct {
	secretKey string
}

// NewJWTMaker creates a new JWTMaker
func NewJWTMaker(secretKey string) (Maker, error) {
	if len(secretKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must be at least %d characters", minSecretKeySize)
	}
	return &JWTMaker{secretKey}, nil
}

// CreateToken creates a new token for a specific username and duration
func (j *JWTMaker) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	claims, err := NewClaims(username, duration)
	uid, err := uuid.Parse(claims.ID)
	if err != nil {
		return "", nil, err
	}
	payload := &Payload{
		ID:        uid,
		Username:  claims.Username,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiredAt: claims.ExpiresAt.Time,
	}
	if err != nil {
		return "", payload, err
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := jwtToken.SignedString([]byte(j.secretKey))
	return token, payload, err
}

// VerifyToken checks if the token is valid or not
func (j *JWTMaker) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return []byte(j.secretKey), nil
	}

	jwtToken, err := jwt.ParseWithClaims(token, &CustomClaims{}, keyFunc)
	if err != nil {
		return nil, err
	}

	customClaims, ok := jwtToken.Claims.(*CustomClaims)
	if !ok {
		return nil, err
	}

	uID, err := uuid.Parse(customClaims.ID)
	if err != nil {
		return nil, err
	}

	payload := &Payload{
		ID:        uID,
		Username:  customClaims.Username,
		IssuedAt:  customClaims.IssuedAt.Time,
		ExpiredAt: customClaims.ExpiresAt.Time,
	}

	return payload, nil
}
