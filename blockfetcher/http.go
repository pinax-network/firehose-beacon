package blockfetcher

import (
	"context"
	"fmt"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/rs/zerolog"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"go.uber.org/zap"
	"strconv"
	"time"
)

const (
	HeadBlock      = "head"
	FinalizedBlock = "finalized"
)

type HttpFetcher struct {
	httpClient               eth2client.Service
	latestConfirmedSlot      uint64
	latestFinalizedSlot      uint64
	latestBlockRetryInterval time.Duration
	fetchInterval            time.Duration
	lastFetchAt              time.Time
	logger                   *zap.Logger
}

func NewHttp(httpClient eth2client.Service, fetchInterval time.Duration, latestBlockRetryInterval time.Duration, logger *zap.Logger) *HttpFetcher {
	f := &HttpFetcher{
		httpClient:               httpClient,
		fetchInterval:            fetchInterval,
		latestBlockRetryInterval: latestBlockRetryInterval,
		logger:                   logger,
	}
	return f
}

func (f *HttpFetcher) IsBlockAvailable(requestedSlot uint64) bool {
	f.logger.Info("checking if block is available", zap.Uint64("request_block_num", requestedSlot), zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot))
	return requestedSlot <= f.latestConfirmedSlot
}

func (f *HttpFetcher) Fetch(ctx context.Context, requestedSlot uint64) (out *pbbstream.Block, skip bool, err error) {
	f.logger.Info("fetching block", zap.Uint64("block_num", requestedSlot))

	sleepDuration := time.Duration(0)
	for f.latestConfirmedSlot < requestedSlot {
		time.Sleep(sleepDuration)

		headBlockHeader, err := f.fetchBlockHeader(ctx, HeadBlock)
		if err != nil {
			return nil, false, fmt.Errorf("fetching head block num: %w", err)
		}

		f.latestConfirmedSlot = uint64(headBlockHeader.Header.Message.Slot)
		f.logger.Info("got latest confirmed slot block", zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot), zap.Uint64("requested_block_num", requestedSlot))

		if f.latestConfirmedSlot >= requestedSlot {
			break
		}
		sleepDuration = f.latestBlockRetryInterval
	}

	if f.latestFinalizedSlot < requestedSlot {

		finalizedBlockHeader, err := f.fetchBlockHeader(ctx, FinalizedBlock)
		if err != nil {
			return nil, false, fmt.Errorf("fetching finalized block num: %w", err)
		}

		f.latestFinalizedSlot = uint64(finalizedBlockHeader.Header.Message.Slot)
		f.logger.Info("got latest finalized slot block", zap.Uint64("latest_finalized_slot", f.latestFinalizedSlot), zap.Uint64("requested_block_num", requestedSlot))
	}

	f.logger.Info("fetching block", zap.Uint64("block_num", requestedSlot), zap.Uint64("latest_finalized_slot", f.latestFinalizedSlot), zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot))

	// todo figure out if we need to handle skipped blocks

	signedBlock, err := f.fetchSignedBlock(ctx, strconv.FormatUint(requestedSlot, 10))
	if err != nil {
		return nil, false, fmt.Errorf("fetching signed block: %w", err)
	}

	blockHeader, err := f.fetchBlockHeader(ctx, strconv.FormatUint(requestedSlot, 10))
	if err != nil {
		return nil, false, fmt.Errorf("fetching block header: %w", err)
	}

	blobSidecars, err := f.fetchBlobSidecars(ctx, strconv.FormatUint(requestedSlot, 10))
	if err != nil {
		return nil, false, fmt.Errorf("fetching blob sidecars: %w", err)
	}

	//blockResult, skip, err := f.fetch(ctx, requestedSlot)
	//if err != nil {
	//	return nil, false, fmt.Errorf("fetching block %d: %w", requestedSlot, err)
	//}
	//
	//if skip {
	//	return nil, true, nil
	//}
	//
	//if blockResult == nil {
	//	panic("blockResult is nil and skip is false. This should not happen.")
	//}

	block, err := toBlock(requestedSlot, f.latestFinalizedSlot, blockHeader, signedBlock, blobSidecars)
	if err != nil {
		return nil, false, fmt.Errorf("decoding block %d: %w", requestedSlot, err)
	}

	f.logger.Info("fetched block", zap.Uint64("slot", requestedSlot))
	return block, false, nil
}

func (f *HttpFetcher) fetchBlockHeader(ctx context.Context, block string) (*v1.BeaconBlockHeader, error) {
	if provider, isProvider := f.httpClient.(eth2client.BeaconBlockHeadersProvider); isProvider {
		blockHeaderResponse, err := provider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return blockHeaderResponse.Data, nil
	}

	return nil, fmt.Errorf("failed to fetch block header, no BeaconBlockHeadersProvider available")
}

func (f *HttpFetcher) fetchSignedBlock(ctx context.Context, block string) (*deneb.BeaconBlock, error) {
	if provider, isProvider := f.httpClient.(eth2client.SignedBeaconBlockProvider); isProvider {
		signedBlockResponse, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return signedBlockResponse.Data.Deneb.Message, nil
	}

	return nil, fmt.Errorf("failed to fetch signed block, no SignedBeaconBlockProvider available")
}

func (f *HttpFetcher) fetchBlobSidecars(ctx context.Context, block string) ([]*deneb.BlobSidecar, error) {
	if provider, isProvider := f.httpClient.(eth2client.BlobSidecarsProvider); isProvider {
		blobSidecarResponse, err := provider.BlobSidecars(ctx, &api.BlobSidecarsOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return blobSidecarResponse.Data, nil
	}

	return nil, fmt.Errorf("failed to fetch blob sidecar, no BlobSidecarsProvider available")
}

func main() {
	// Provide a cancellable context to the creation function.
	ctx := context.Background()
	client, err := http.New(ctx,
		// WithAddress supplies the address of the beacon node, as a URL.
		http.WithAddress("http://localhost:5052/"),
		// LogLevel supplies the level of logging to carry out.
		http.WithLogLevel(zerolog.DebugLevel),
		http.WithTimeout(10*time.Second),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Connected to %s\n", client.Name())

	// Client functions have their own interfaces.  Not all functions are
	// supported by all clients, so checks should be made for each function when
	// casting the service to the relevant interface.
	//if provider, isProvider := client.(eth2client.GenesisProvider); isProvider {
	//	genesisResponse, err := provider.Genesis(ctx, &api.GenesisOpts{})
	//	if err != nil {
	//		// Errors may be API errors, in which case they will have more detail
	//		// about the failure.
	//		var apiErr *api.Error
	//		if errors.As(err, &apiErr) {
	//			switch apiErr.StatusCode {
	//			case 404:
	//				panic("genesis not found")
	//			case 503:
	//				panic("node is syncing")
	//			}
	//		}
	//		panic(err)
	//	}
	//	fmt.Printf("Genesis time is %v\n", genesisResponse.Data.GenesisTime)
	//}

	if provider, isProvider := client.(eth2client.SignedBeaconBlockProvider); isProvider {
		blobSidecarsResponse, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{Block: "finalized"})
		if err != nil {
			panic(err)
		}

		fmt.Printf("Received Block %v\n", blobSidecarsResponse.Data.Deneb.Message.Slot)
	}

	if provider, isProvider := client.(eth2client.BlobSidecarsProvider); isProvider {
		blobSidecarsResponse, err := provider.BlobSidecars(ctx, &api.BlobSidecarsOpts{Block: "finalized"})
		if err != nil {
			panic(err)
		}

		for _, blob := range blobSidecarsResponse.Data {
			fmt.Printf("Received Blob %v\n", blob.Index)
		}
	}

	// You can also access the struct directly if required.
	httpClient := client.(*http.Service)
	genesisResponse, err := httpClient.Genesis(ctx, &api.GenesisOpts{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Genesis validators root is %s\n", genesisResponse.Data.GenesisValidatorsRoot)

	// Cancelling the context passed to New() frees up resources held by the
	// client, closes connections, clears handlers, etc.

}
