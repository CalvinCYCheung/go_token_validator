package converter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

type SupportedReturnTypes interface {
	*rsa.PublicKey | *rsa.PrivateKey | string
}

type SupportedParamsTypes interface {
	[]byte | model.PrivateKeyJWK | model.PublicKeyJWK
}

type Converter[R SupportedReturnTypes, P SupportedParamsTypes] interface {
	Convert(data P) (R, error)
}

type StringConverter struct{}

func (str StringConverter) Convert(data []byte) (string, error) {
	return string(data), nil
}

type RsaPublicKeyConverter struct{}

func (converter RsaPublicKeyConverter) Convert(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid pem block")
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

type PublicKeyJwkToKeyConverter struct{}

func (converter PublicKeyJwkToKeyConverter) Convert(data []byte) (*rsa.PublicKey, error) {
	var jwk model.PublicKeyJWK
	err := json.Unmarshal(data, &jwk)
	if err != nil {
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawStdEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	key := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: int(big.NewInt(0).SetBytes(e).Int64()),
	}
	return key, nil
}

type RsaPrivateKeyConverter struct{}

func (converter RsaPrivateKeyConverter) Convert(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid pem block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

type PrivateKeyJwkToKeyConverter struct{}

func (converter PrivateKeyJwkToKeyConverter) Convert(data []byte) (*rsa.PrivateKey, error) {
	var jwk model.PrivateKeyJWK
	err := json.Unmarshal(data, &jwk)
	if err != nil {
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawStdEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	p, err := base64.RawURLEncoding.DecodeString(jwk.P)
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
		D: big.NewInt(0).SetBytes(d),
		PublicKey: rsa.PublicKey{
			N: big.NewInt(0).SetBytes(n),
			E: int(big.NewInt(0).SetBytes(e).Int64()),
		},
		Primes: []*big.Int{
			big.NewInt(0).SetBytes(p),
			big.NewInt(0).SetBytes(q),
		},
	}
	key.Precompute()
	return key, key.Validate()
}

type JwkToPrivateKeyConverter struct{}

func (converter JwkToPrivateKeyConverter) Convert(jwk model.PrivateKeyJWK) (*rsa.PrivateKey, error) {

	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		fmt.Println("d", err)
		return nil, err
	}
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		fmt.Println("n", err)
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		fmt.Println("e", err)
		return nil, err
	}
	p, err := base64.RawURLEncoding.DecodeString(jwk.P)
	if err != nil {
		fmt.Println("p", err)
		return nil, err
	}
	q, err := base64.RawURLEncoding.DecodeString(jwk.Q)
	if err != nil {
		fmt.Println("q", err)
		return nil, err
	}

	key := &rsa.PrivateKey{
		D: big.NewInt(0).SetBytes(d),
		PublicKey: rsa.PublicKey{
			N: big.NewInt(0).SetBytes(n),
			E: int(big.NewInt(0).SetBytes(e).Int64()),
		},
		Primes: []*big.Int{
			big.NewInt(0).SetBytes(p),
			big.NewInt(0).SetBytes(q),
		},
	}
	key.Precompute()
	return key, key.Validate()
}

type JwkToPublicKeyConverter struct{}

func (converter JwkToPublicKeyConverter) Convert(jwk model.PublicKeyJWK) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawStdEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	key := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(n),
		E: int(big.NewInt(0).SetBytes(e).Int64()),
	}
	return key, nil
}
