package s3

import "github.com/aws/aws-sdk-go-v2/service/s3"

func InitS3Client() *s3.Client {
	cfg := initAws()
	s3Client := s3.NewFromConfig(*cfg)
	return s3Client
}
