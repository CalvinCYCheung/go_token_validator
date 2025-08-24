package converter

import (
	"crypto/rsa"

	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

type ConverterFactoryInterface interface {
	CreateStringConverter() Converter[string, []byte]
	CreateRsaPublicKeyConverter() Converter[*rsa.PublicKey, []byte]
	CreateJwkToPublicKeyConverter() Converter[*rsa.PublicKey, []byte]
	JwkToPrivateConverter() Converter[*rsa.PrivateKey, model.PrivateKeyJWK]
}

type ConvertFactory struct{}

func (factory ConvertFactory) CreateStringConverter() Converter[string, []byte] {
	return StringConverter{}
}

func (factory ConvertFactory) CreateRsaPublicKeyConverter() Converter[*rsa.PublicKey, []byte] {
	return RsaPublicKeyConverter{}
}

func (factory ConvertFactory) CreateJwkToPublicKeyConverter() Converter[*rsa.PublicKey, []byte] {
	return PublicKeyJwkToKeyConverter{}
}

func (factory ConvertFactory) JwkToPrivateConverter() Converter[*rsa.PrivateKey, model.PrivateKeyJWK] {
	return JwkToPrivateKeyConverter{}
}

func (factory ConvertFactory) JwkToPublicConverter() Converter[*rsa.PublicKey, model.PublicKeyJWK] {
	return JwkToPublicKeyConverter{}
}
