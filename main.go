package main

import "api_validator/v1/convertor"

func main() {
	factory := convertor.ConvertFactory{}
	_ = factory.CreateJwkToPublicKeyConvertor()

	// convertorService := convertor_factory.ConvertFactory{}
	// factory := convertorService.ConvertFactory{}
	// _ = factory.CreateJwkToPublicKeyConvertor()

}
