package backgroundfetcher

import (
	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

type supportedType interface {
	*model.JWKS | *model.PrivateKeyJWK
}
type BackgroundFetcher interface {
	Start()
	Stop()
}
