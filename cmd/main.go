package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CalvinCYCheung/go_token_validator/internal/generator"
	"github.com/CalvinCYCheung/go_token_validator/internal/model"
	storage "github.com/CalvinCYCheung/go_token_validator/internal/storage"
	"github.com/CalvinCYCheung/go_token_validator/internal/validator"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
)

func main() {
	tokenGenerator := generator.NewTokenGenerator(15 * time.Minute)
	validator := validator.NewRsaKeyValidator(15 * time.Minute)
	router := gin.Default()
	router.POST("/token", func(ctx *gin.Context) {
		token, err := tokenGenerator.Generate()
		if err != nil {
			ctx.JSON(500, gin.H{"error": err.Error()})
			ctx.Abort()
			return
		}
		ctx.JSON(200, gin.H{"token": token})
	})
	router.POST("/validate", func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.JSON(400, gin.H{"error": "Token is required"})
			c.Abort()
			return
		}
		isValid, err := validator.Validate(token)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		if !isValid {
			c.JSON(401, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		c.JSON(200, gin.H{"isValid": isValid})
	})
	router.Run(":5080")
	// tokenGenerator := generator.NewTokenGenerator(15 * time.Minute)
	// start := time.Now()
	// fmt.Println("start: ", start)
	// token, err := tokenGenerator.Generate()
	// if err != nil {
	// 	fmt.Println("error: ", err)
	// }
	// fmt.Println("token: ", token)
	// fmt.Println(time.Since(start))

	// fmt.Println("--------------------------------")

	// validator := validator.NewRsaKeyValidator(15 * time.Minute)
	// start = time.Now()
	// fmt.Println("start: ", start)
	// isValid, err := validator.Validate(token)
	// if err != nil {
	// 	fmt.Println("error: ", err)
	// }
	// fmt.Println("isValid: ", isValid)
	// fmt.Println(time.Since(start))
	// var wg sync.WaitGroup
	// var stopChan = make(chan struct{})
	// var isStarted int32
	// start(&wg, 15*time.Second, false, stopChan, &isStarted)
	// time.Sleep(3 * time.Second)
	// start(&wg, 2*time.Second, true, stopChan, &isStarted)
	// time.Sleep(20 * time.Second)
	// close(stopChan)
	// wg.Wait()
}

func start(wg *sync.WaitGroup, duration time.Duration, isDecrement bool, stopChan chan struct{}, isStarted *int32) {
	if !atomic.CompareAndSwapInt32(isStarted, 0, 1) {
		fmt.Println("already started")
		return
	}
	atomic.StoreInt32(isStarted, 1)
	test(wg, duration, isDecrement, stopChan)
}

func test(wg *sync.WaitGroup, duration time.Duration, isDecrement bool, stopChan chan struct{}) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(duration)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				key, err := fetchPrivateKey()
				if err != nil {
					fmt.Println("error: ", err)
				}
				fmt.Println("key: ", key)
				// mockFetch()
			case <-stopChan:
				fmt.Println("stop")
				return
			}
		}
	}()
}

func mockFetch() string {
	time.Sleep(1 * time.Second)
	return "fetch"
}

func fetchPrivateKey() (*model.PrivateKeyJWK, error) {
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
	fmt.Println("keyName: ", keyName)
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
