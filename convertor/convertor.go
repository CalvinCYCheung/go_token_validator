package convertor

import (
	"api_validator/v1/model"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
)

type Convertor[T any] interface {
	Convert(data []byte) (T, error)
}

type StringConvertor struct{}

func (str StringConvertor) Convert(data []byte) (string, error) {
	return string(data), nil
}

type RsaPublicKeyConvertor struct{}

func (convertor RsaPublicKeyConvertor) Convert(data []byte) (*rsa.PublicKey, error) {
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

type PublicKeyJwkToKeyConvertor struct{}

func (convertor PublicKeyJwkToKeyConvertor) Convert(data []byte) (*rsa.PublicKey, error) {
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
