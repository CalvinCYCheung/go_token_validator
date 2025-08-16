package convertor

import "crypto/rsa"

type ConverterFactoryInterface interface {
	CreateStringConvertor() Convertor[string]
	CreateRsaPublicKeyConvertor() Convertor[*rsa.PublicKey]
	CreateJwkToPublicKeyConvertor() Convertor[*rsa.PublicKey]
}

type ConvertFactory struct{}

func (factory ConvertFactory) CreateStringConvertor() Convertor[string] {
	return StringConvertor{}
}

func (factory ConvertFactory) CreateRsaPublicKeyConvertor() Convertor[*rsa.PublicKey] {
	return RsaPublicKeyConvertor{}
}

func (factory ConvertFactory) CreateJwkToPublicKeyConvertor() Convertor[*rsa.PublicKey] {
	return PublicKeyJwkToKeyConvertor{}
}
