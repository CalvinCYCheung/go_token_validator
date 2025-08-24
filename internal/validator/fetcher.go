package validator

import (
	"fmt"
	"sync"
	"time"

	"github.com/CalvinCYCheung/go_token_validator/internal/model"
)

type ValidatorBackgroundFetcher struct {
	jwks   *model.JWKS
	fetch  func() (*model.JWKS, error)
	ticker *time.Ticker
	result chan *model.JWKS
	wg     sync.WaitGroup
}

func (b *ValidatorBackgroundFetcher) Start() {
	fmt.Println("Fetcher Started")
	b.wg.Add(1)
	go func() {
		defer func() {
			fmt.Println("Fetcher Done")
			close(b.result)
			b.wg.Done()
		}()
		defer b.ticker.Stop()
		for {
			select {
			case <-b.ticker.C:
				jwks, err := b.fetch()
				if err != nil {
					fmt.Println("error: ", err)
					continue
				}
				fmt.Println("Fetched Jwks")
				b.result <- jwks
			}
		}
	}()
}

func (b *ValidatorBackgroundFetcher) Stop() {
	b.ticker.Stop()
	b.wg.Wait()
}
