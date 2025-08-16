package main

import "github.com/CalvinCYCheung/go_token_validator/convertor"

func main() {
	factory := convertor.ConvertFactory{}
	_ = factory.CreateJwkToPublicKeyConvertor()

	// convertorService := convertor_factory.ConvertFactory{}
	// factory := convertorService.ConvertFactory{}
	// _ = factory.CreateJwkToPublicKeyConvertor()

}
