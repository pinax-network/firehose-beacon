package blockfetcher

import (
	"context"
	"fmt"
	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
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

func (f *HttpFetcher) fetchSignedBlock(ctx context.Context, block string) (*spec.VersionedSignedBeaconBlock, error) {
	if provider, isProvider := f.httpClient.(eth2client.SignedBeaconBlockProvider); isProvider {
		signedBlockResponse, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return signedBlockResponse.Data, nil
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
