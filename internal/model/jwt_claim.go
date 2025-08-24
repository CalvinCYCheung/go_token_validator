package model

import "github.com/golang-jwt/jwt/v5"

type JwtClaim struct {
	Kid string `json:"kid"`
	jwt.RegisteredClaims
}
