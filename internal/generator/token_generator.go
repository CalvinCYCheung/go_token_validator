package generator

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	backgroundfetcher "github.com/CalvinCYCheung/go_token_validator/internal/background_fetcher"
	"github.com/CalvinCYCheung/go_token_validator/internal/converter"
	"github.com/CalvinCYCheung/go_token_validator/internal/model"
	storage "github.com/CalvinCYCheung/go_token_validator/internal/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt/v5"
)

type TokenGenerator interface {
	Generate(token string) (string, error)
}

type TokenGeneratorImpl struct {
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	converter  converter.Converter[*rsa.PrivateKey, model.PrivateKeyJWK]
	kid        string
	fetcher    backgroundfetcher.BackgroundFetcher
}

func NewTokenGenerator(refreshInterval time.Duration) *TokenGeneratorImpl {
	key, err := fetchKey()
	if err != nil {
		panic(err)
	}
	factory := converter.ConvertFactory{}
	converter := factory.JwkToPrivateConverter()
	privateKey, err := converter.Convert(*key)
	if err != nil {
		panic(err)
	}
	result := make(chan *model.PrivateKeyJWK)
	fetcher := &PrivateKeyFetcher{
		fetch:  fetchKey,
		result: result,
		ticker: time.NewTicker(refreshInterval),
	}
	tokenGenerator := &TokenGeneratorImpl{
		converter:  converter,
		privateKey: privateKey,
		kid:        key.Kid,
		fetcher:    fetcher,
	}
	fetcher.Start()
	tokenGenerator.fetchPrivateKey(result)
	return tokenGenerator
}

func (t *TokenGeneratorImpl) Generate() (string, error) {
	claim := model.JwtClaim{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "1234567890",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)
	token.Header["kid"] = t.kid
	tokenStr, err := token.SignedString(t.privateKey)
	if err != nil {
		return "", err
	}
	return tokenStr, nil
}

func (t *TokenGeneratorImpl) getPrivateKey() *rsa.PrivateKey {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.privateKey
}

func (t *TokenGeneratorImpl) updatePrivateKey(privateKey *rsa.PrivateKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.privateKey = privateKey
}

func (t *TokenGeneratorImpl) fetchPrivateKey(result chan *model.PrivateKeyJWK) {
	go func(ch chan *model.PrivateKeyJWK) {
		for {
			select {
			case jwks := <-ch:
				privateKey, err := t.converter.Convert(*jwks)
				if err != nil {
					fmt.Println("background convert error: ", err)
					continue
				}
				t.updatePrivateKey(privateKey)
				t.privateKey = privateKey
			}
		}
	}(result)
}

func fetchKey() (*model.PrivateKeyJWK, error) {
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
	// fmt.Println(jwks)
	keyName := jwks.Keys[0].Kid
	// fmt.Println("keyName: ", keyName)
	res, err = client.GetObject(ctx, &s3.GetObjectInput{
		Key:    aws.String(fmt.Sprintf("jwk-private-%s.json", keyName)),
		Bucket: aws.String("go-api-bucket-v1-21-6-2025"),
	})
	if err != nil {
		return nil, err
	}
	body, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var privateKey model.PrivateKeyJWK
	err = json.Unmarshal(body, &privateKey)
	if err != nil {
		return nil, err
	}
	return &privateKey, nil
}
