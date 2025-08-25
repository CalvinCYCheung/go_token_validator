package generator

import (
	"fmt"
	"sync"
	"time"

	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

func NewPrivateKeyFetcher(
	refreshInterval time.Duration,
	fetch func() (*model.PrivateKeyJWK, error),
	result chan *model.PrivateKeyJWK,
) *PrivateKeyFetcher {
	return &PrivateKeyFetcher{
		fetch:  fetch,
		ticker: time.NewTicker(refreshInterval),
		result: result,
	}
}

type PrivateKeyFetcher struct {
	result chan *model.PrivateKeyJWK
	ticker *time.Ticker
	fetch  func() (*model.PrivateKeyJWK, error)
	wg     sync.WaitGroup
}

func (p *PrivateKeyFetcher) Start() {
	p.wg.Add(1)
	go func() {
		defer func() {
			p.ticker.Stop()
			close(p.result)
			p.wg.Done()
		}()
		for {
			select {
			case <-p.ticker.C:
				jwk, err := p.fetch()
				if err != nil {
					fmt.Println("error: ", err)
					continue
				}
				p.result <- jwk
			}
		}
	}()
}

func (p *PrivateKeyFetcher) Stop() {
	p.ticker.Stop()
	p.wg.Wait()
}
