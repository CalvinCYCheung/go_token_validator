// This file demonstrates better approaches to the reflection-based key parsing
// Run with: go run improved_examples.go
package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

// Approach 1: Interface-based with type-specific methods
type RsaKeyParser interface {
	ParsePublicKey(data []byte) (*rsa.PublicKey, error)
	ParsePrivateKey(data []byte) (*rsa.PrivateKey, error)
}

type RsaParser struct{}

func (p RsaParser) ParsePublicKey(data []byte) (*rsa.PublicKey, error) {
	jwk := model.PublicKeyJWK{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: int(big.NewInt(0).SetBytes(e).Uint64()),
	}, nil
}

func (p RsaParser) ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	jwk := model.PrivateKeyJWK{}
	if err := json.Unmarshal(data, &jwk); err != nil {
		return nil, err
	}

	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	p_bytes, err := base64.RawURLEncoding.DecodeString(jwk.P)
	if err != nil {
		return nil, err
	}
	q, err := base64.RawURLEncoding.DecodeString(jwk.Q)
	if err != nil {
		return nil, err
	}
	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, err
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: big.NewInt(0).SetBytes(n),
			E: int(big.NewInt(0).SetBytes(e).Uint64()),
		},
		D: big.NewInt(0).SetBytes(d),
		Primes: []*big.Int{
			big.NewInt(0).SetBytes(p_bytes),
			big.NewInt(0).SetBytes(q),
		},
	}
	key.Precompute()
	return key, key.Validate()
}

// Approach 2: Type-safe generics with constraints
// Note: Using the same RsaKey interface as in main.go

// Create a type-safe parser for each specific type
type PublicKeyParser struct{}
type PrivateKeyParser struct{}

func (p PublicKeyParser) Parse(data []byte) (*rsa.PublicKey, error) {
	parser := RsaParser{}
	return parser.ParsePublicKey(data)
}

func (p PrivateKeyParser) Parse(data []byte) (*rsa.PrivateKey, error) {
	parser := RsaParser{}
	return parser.ParsePrivateKey(data)
}

// We'll reference the RsaKey type from main.go package scope
// For this example, let's define our own constraint locally to avoid conflicts
type RsaKeyConstraint interface {
	*rsa.PrivateKey | *rsa.PublicKey
}

// Generic function that works with any parser
func ParseKey[T RsaKeyConstraint, P interface{ Parse([]byte) (T, error) }](parser P, data []byte) (T, error) {
	return parser.Parse(data)
}

// Approach 3: Factory pattern with type assertion (compile-time safe)
func NewKeyParser[T RsaKeyConstraint]() interface{ Parse([]byte) (T, error) } {
	var zero T
	switch any(zero).(type) {
	case *rsa.PublicKey:
		return any(PublicKeyParser{}).(interface{ Parse([]byte) (T, error) })
	case *rsa.PrivateKey:
		return any(PrivateKeyParser{}).(interface{ Parse([]byte) (T, error) })
	default:
		panic("unsupported key type")
	}
}

// Approach 4: Functional approach with higher-order functions
func ParsePublicKeyFromJWK(data []byte) (*rsa.PublicKey, error) {
	parser := RsaParser{}
	return parser.ParsePublicKey(data)
}

func ParsePrivateKeyFromJWK(data []byte) (*rsa.PrivateKey, error) {
	parser := RsaParser{}
	return parser.ParsePrivateKey(data)
}

// Usage examples
func demonstrateApproaches() {
	publicKeyData := `{"alg": "RS256", "kid": "test", "kty": "RSA", "n": "xsBhkZbPNti8JwzD2572fd9BgltvXpliTRipbbdQZin2Vm90NRWTHpdVvhBQaR3IKo4YCZbyVzkbRhPlA3KVVAGQFoA3rnB7t0_Gs3dJ7WTZNLL10DzJ5RXlCLjjFXmk73XIahEEyyAmbMmcTicJOxzTZMPkG6YvmiDSdI3SJpe9BqDhu93IKbYaBPdRJcDttRRlo6prIsIPa2c57g1Y0M02eF50WsZLxXHJYYazvx6n4Ha4E5fRu0FQnVmlj1WmmpAqWNeTFOn7nVFVJ0hxroVMBCcKvnVrAioUk5ukEttV12MfqzkVw3XqR56ReBkaIIWXdRKvKUeofWUEeh23GQ", "e": "AQAB", "use": "sig"}`

	// Approach 1: Direct interface usage
	fmt.Println("=== Approach 1: Interface-based ===")
	parser := RsaParser{}
	pubKey, err := parser.ParsePublicKey([]byte(publicKeyData))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Public key parsed successfully: %T\n", pubKey)
	}

	// Approach 2: Type-safe generics
	fmt.Println("\n=== Approach 2: Type-safe generics ===")
	pubKey2, err := ParseKey[*rsa.PublicKey](PublicKeyParser{}, []byte(publicKeyData))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Public key parsed successfully: %T\n", pubKey2)
	}

	// Approach 3: Factory pattern
	fmt.Println("\n=== Approach 3: Factory pattern ===")
	keyParser := NewKeyParser[*rsa.PublicKey]()
	pubKey3, err := keyParser.Parse([]byte(publicKeyData))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Public key parsed successfully: %T\n", pubKey3)
	}

	// Approach 4: Functional approach
	fmt.Println("\n=== Approach 4: Functional approach ===")
	pubKey4, err := ParsePublicKeyFromJWK([]byte(publicKeyData))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("Public key parsed successfully: %T\n", pubKey4)
	}
}

// Rename to avoid conflict with main.go
func runExamples() {
	demonstrateApproaches()
}
