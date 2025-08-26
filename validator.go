package tokenservice

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	backgroundfetcher "github.com/CalvinCYCheung/go_token_validator/internal/background_fetcher"

	"github.com/CalvinCYCheung/go_token_validator/internal/converter"
	"github.com/CalvinCYCheung/go_token_validator/internal/model"
	storage "github.com/CalvinCYCheung/go_token_validator/internal/storage"
	validator "github.com/CalvinCYCheung/go_token_validator/internal/validator"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
)

type Validator interface {
	Validate(token string) (bool, error)
}

func NewRsaKeyValidator(
	refresh time.Duration,
	fetch func() (*model.JWKS, error),
) *RsaKeyValidator {
	jwks, err := fetch() // Init fetch jwks
	if err != nil {
		panic(err)
	}
	result := make(chan *model.JWKS)
	fetcher := validator.NewValidatorBackgroundFetcher(refresh, fetchJwk, result)
	factory := converter.ConvertFactory{}
	converter := factory.JwkToPublicConverter()
	validator := &RsaKeyValidator{
		jwks:      jwks,
		converter: converter,
		fetcher:   fetcher,
	}

	fetcher.Start()
	validator.backgroundUpdates(result)

	return validator
}

type RsaKeyValidator struct {
	mu        sync.RWMutex
	jwks      *model.JWKS
	converter converter.Converter[*rsa.PublicKey, model.PublicKeyJWK]
	fetcher   backgroundfetcher.BackgroundFetcher
}

func (v *RsaKeyValidator) Validate(token string) (bool, error) {
	_, err := jwt.ParseWithClaims(token, &model.JwtClaim{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("invalid signing method")
		}
		exp, err := t.Claims.GetExpirationTime()
		if err != nil {
			return nil, err
		}
		if time.Now().After(exp.Time) {
			return nil, errors.New("token is expired")
		}
		jwks := v.getJwks()
		for _, pkj := range jwks.Keys {
			if pkj.Kid == t.Header["kid"] {
				pk, err := v.converter.Convert(pkj)
				if err != nil {
					return nil, err
				}
				return pk, nil
			}
		}
		return nil, errors.New("kid not found")
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (v *RsaKeyValidator) backgroundUpdates(result chan *model.JWKS) {
	go func(ch chan *model.JWKS) {
		for jwks := range ch {
			fmt.Println("Updating Jwks")
			v.updateJwks(jwks)
		}
	}(result)
}

func (v *RsaKeyValidator) getJwks() *model.JWKS {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.jwks
}

func (v *RsaKeyValidator) updateJwks(jwks *model.JWKS) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.jwks = jwks
}

func fetchJwk() (*model.JWKS, error) {
	ctx := context.Background()

	client := storage.InitS3Client()
	res, err := client.GetObject(ctx, &s3.GetObjectInput{
		Key:    aws.String(".well-known/jwks.json"),
		Bucket: aws.String("goback-end-shared-bucket"),
	})
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var jwks model.JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}
	return &jwks, nil
}
