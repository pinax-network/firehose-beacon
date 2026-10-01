package blockfetcher

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"go.uber.org/zap"
)

const (
	HeadBlock      = "head"
	FinalizedBlock = "finalized"
)

type HttpFetcher struct {
	latestConfirmedSlot      uint64
	latestFinalizedSlot      uint64
	latestBlockRetryInterval time.Duration
	fetchInterval            time.Duration
	lastFetchAt              time.Time
	logger                   *zap.Logger
	seenBlockNums            *sync.Map
	// seenBidBlockHashes maps the roots of seen Gloas blocks to the execution block hash of their bid, needed to derive
	// the Firehose block ID of a block's parent
	seenBidBlockHashes *sync.Map
	genesisTimestamp   uint64
	blockTime          uint64
	ignoreMissingBlobs bool
	// gloasForkSlot is the first slot of the Gloas fork, math.MaxUint64 if the chain has no Gloas fork scheduled
	gloasForkSlot uint64
}

func NewHttp(httpClient eth2client.Service, fetchInterval time.Duration, latestBlockRetryInterval time.Duration, ignoreMissingBlobs bool, logger *zap.Logger) (*HttpFetcher, error) {
	f := &HttpFetcher{
		fetchInterval:            fetchInterval,
		latestBlockRetryInterval: latestBlockRetryInterval,
		logger:                   logger,
		seenBlockNums:            &sync.Map{},
		seenBidBlockHashes:       &sync.Map{},
		ignoreMissingBlobs:       ignoreMissingBlobs,
		gloasForkSlot:            math.MaxUint64,
	}
	err := f.fetchBlockTimes(httpClient)
	if err != nil {
		return nil, err
	}

	return f, nil
}

// fetchBlockTimes receives the genesis time and the slot duration from the beacon node. This allows us to set the slot
// time in the Firehose blocks for specs that do not include the execution payload (before Bellatrix and from Gloas
// onwards) to genesisTime + (slotNumber * blockTime). It also detects the Gloas fork slot.
func (f *HttpFetcher) fetchBlockTimes(httpClient eth2client.Service) error {
	f.logger.Info("initializing block fetcher")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	genesis, err := f.fetchGenesis(ctx, httpClient)
	if err != nil {
		return fmt.Errorf("failed to fetch genesis: %w", err)
	}
	f.genesisTimestamp = uint64(genesis.GenesisTime.Unix())

	chainSpec, err := f.fetchSpec(ctx, httpClient)
	if err != nil {
		return fmt.Errorf("failed to fetch spec: %w", err)
	}
	if gloasForkEpoch, ok := chainSpec["GLOAS_FORK_EPOCH"].(uint64); ok {
		if slotsPerEpoch, ok := chainSpec["SLOTS_PER_EPOCH"].(uint64); ok && slotsPerEpoch > 0 && gloasForkEpoch < math.MaxUint64/slotsPerEpoch {
			f.gloasForkSlot = gloasForkEpoch * slotsPerEpoch
		}
	}
	f.logger.Info("detected gloas fork slot", zap.Uint64("gloas_fork_slot", f.gloasForkSlot))

	secondsPerSlot, ok := chainSpec["SECONDS_PER_SLOT"].(time.Duration)
	if !ok || secondsPerSlot <= 0 {
		return errors.New("missing SECONDS_PER_SLOT in spec")
	}
	f.blockTime = uint64(secondsPerSlot.Seconds())
	f.logger.Info("detected block time", zap.Uint64("block_time", f.blockTime))

	return nil
}

func (f *HttpFetcher) IsBlockAvailable(requestedSlot uint64) bool {
	f.logger.Info("checking if block is available", zap.Uint64("request_block_num", requestedSlot), zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot))
	return f.requiredHeadSlot(requestedSlot) <= f.latestConfirmedSlot
}

// requiredHeadSlot returns the head slot the beacon node needs to have reached before the requested slot can be
// fetched. From Gloas onwards, whether a block's execution payload became canonical is only decided by the next
// block, so we need to stay one slot behind the head.
func (f *HttpFetcher) requiredHeadSlot(requestedSlot uint64) uint64 {
	if requestedSlot >= f.gloasForkSlot {
		return requestedSlot + 1
	}
	return requestedSlot
}

// waitForHeadSlot polls the head block header until the beacon node's head has reached the required slot, refreshing
// latestConfirmedSlot on the way.
func (f *HttpFetcher) waitForHeadSlot(ctx context.Context, httpClient eth2client.Service, requiredSlot uint64) error {
	sleepDuration := time.Duration(0)
	for f.latestConfirmedSlot < requiredSlot {
		if sleepDuration > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(sleepDuration):
			}
		}

		headBlockHeader, err := f.fetchBlockHeader(ctx, httpClient, HeadBlock)
		if err != nil {
			return fmt.Errorf("fetching head block num: %w", err)
		}

		f.latestConfirmedSlot = uint64(headBlockHeader.Header.Message.Slot)
		f.logger.Info("got latest confirmed slot block", zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot), zap.Uint64("required_slot", requiredSlot))

		sleepDuration = f.latestBlockRetryInterval
	}

	return nil
}

func (f *HttpFetcher) Fetch(ctx context.Context, httpClient eth2client.Service, requestedSlot uint64) (out *pbbstream.Block, skip bool, err error) {

	if err := f.waitForHeadSlot(ctx, httpClient, f.requiredHeadSlot(requestedSlot)); err != nil {
		return nil, false, err
	}

	sinceLastFetch := time.Since(f.lastFetchAt)
	if sinceLastFetch < f.fetchInterval {
		time.Sleep(f.fetchInterval - sinceLastFetch)
	}

	if f.latestFinalizedSlot < requestedSlot {
		finalizedBlockHeader, err := f.fetchBlockHeader(ctx, httpClient, FinalizedBlock)
		if err != nil {
			return nil, false, fmt.Errorf("fetching finalized block num: %w", err)
		}
		f.latestFinalizedSlot = uint64(finalizedBlockHeader.Header.Message.Slot)
		f.logger.Info("got latest finalized slot block", zap.Uint64("latest_finalized_slot", f.latestFinalizedSlot), zap.Uint64("requested_block_num", requestedSlot))
	}

	f.logger.Info("fetching block", zap.Uint64("block_num", requestedSlot), zap.Uint64("latest_finalized_slot", f.latestFinalizedSlot), zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot))

	// the header tells us the root of the block currently at the requested slot (the signed block does not carry its
	// root), and whether the slot was skipped
	blockHeader, skip, err := f.fetchBlockHeaderAtSlot(ctx, httpClient, requestedSlot)
	if err != nil || skip {
		return nil, skip, err
	}

	// the signed block is requested by the header's root rather than by slot, so that a reorg between the two requests
	// cannot pair the header of one block with the body of another
	signedBlock, err := f.fetchSignedBlock(ctx, httpClient, blockHeader.Root.String())
	if err != nil {
		f.logger.Error("failed to fetch signed block", zap.Error(err), zap.Uint64("slot", requestedSlot), zap.Stringer("root", blockHeader.Root))
		return nil, false, fmt.Errorf("fetching signed block %s: %w", blockHeader.Root, err)
	}

	// the block header also doesn't include the parent slot, so we are going to buffer all seen blocks to avoid sending
	// another request to get the parent block header if possible
	f.seenBlockNums.Store(blockHeader.Root.String(), uint64(blockHeader.Header.Message.Slot))

	parentSlot := uint64(0)
	if blockHeader.Header.Message.Slot > 0 {
		if bufferedSlot, ok := f.seenBlockNums.Load(blockHeader.Header.Message.ParentRoot.String()); ok {
			parentSlot = bufferedSlot.(uint64)
			f.logger.Debug("found parent slot in our buffer", zap.Uint64("slot", requestedSlot), zap.String("parent_root", blockHeader.Header.Message.ParentRoot.String()), zap.Uint64("parent_slot", parentSlot))
		} else {
			f.logger.Debug("missing parent slot in our buffer, requesting from Lighthouse node", zap.Uint64("slot", requestedSlot), zap.String("parent_root", blockHeader.Header.Message.ParentRoot.String()))
			parentBlockHeader, err := f.fetchBlockHeader(ctx, httpClient, blockHeader.Header.Message.ParentRoot.String())
			if err != nil {
				return nil, false, fmt.Errorf("fetching parent block header: %w", err)
			}
			parentSlot = uint64(parentBlockHeader.Header.Message.Slot)
		}
	}

	// From Gloas onwards, the Firehose block ID encodes whether the block's execution payload became canonical (see
	// gloasBlockID), so that firehose-core detects a change of the payload status like any other fork
	blockID := blockHeader.Root.String()
	parentID := blockHeader.Header.Message.ParentRoot.String()

	var envelope *gloas.SignedExecutionPayloadEnvelope
	var blobs []*deneb.Blob
	var blobSidecars []*deneb.BlobSidecar
	if signedBlock.Version >= spec.DataVersionGloas {
		envelope, blobs, err = f.fetchGloasPayload(ctx, httpClient, requestedSlot, blockHeader.Root, signedBlock)
		if err != nil {
			f.logger.Error("failed to fetch gloas execution payload", zap.Error(err), zap.Uint64("slot", requestedSlot))
			return nil, false, fmt.Errorf("fetching gloas execution payload: %w", err)
		}
		blockID = gloasBlockID(blockHeader.Root, envelope != nil)

		if blockHeader.Header.Message.Slot > 0 {
			parentID, err = f.gloasParentBlockID(ctx, httpClient, signedBlock.Gloas.Message)
			if err != nil {
				f.logger.Error("failed to derive parent block id", zap.Error(err), zap.Uint64("slot", requestedSlot))
				return nil, false, fmt.Errorf("deriving parent block id: %w", err)
			}
		}
	} else {
		blobSidecars, err = f.fetchBlobSidecars(ctx, httpClient, strconv.FormatUint(requestedSlot, 10))
		if err != nil {
			if !f.isIgnorableMissingBlobsError(err) {
				f.logger.Error("failed to fetch blob sidecars"+missingBlobsHint, zap.Error(err))
				return nil, false, fmt.Errorf("fetching blob sidecars: %w", err)
			}
			f.logger.Error("failed to fetch blob sidecars, setting to empty array as --ignore-missing-blobs is set", zap.Error(err))
			blobSidecars = []*deneb.BlobSidecar{}
		}
	}

	f.lastFetchAt = time.Now()

	block, err := toBlock(requestedSlot, parentSlot, f.latestFinalizedSlot, f.genesisTimestamp, f.blockTime, blockID, parentID, blockHeader, signedBlock, blobSidecars, envelope, blobs)
	if err != nil {
		f.logger.Error("failed to decode block", zap.Error(err), zap.Uint64("slot", requestedSlot))
		return nil, false, fmt.Errorf("decoding block %d: %w", requestedSlot, err)
	}

	f.logger.Info("fetched block", zap.Uint64("slot", requestedSlot), zap.Uint64("parent_slot", parentSlot), zap.Any("timestamp", block.Timestamp))
	return block, false, nil
}

// fetchBlockHeaderAtSlot fetches the block header at the given slot, reporting a 404 as a skipped slot.
func (f *HttpFetcher) fetchBlockHeaderAtSlot(ctx context.Context, httpClient eth2client.Service, slot uint64) (header *v1.BeaconBlockHeader, skip bool, err error) {
	blockHeader, err := f.fetchBlockHeader(ctx, httpClient, strconv.FormatUint(slot, 10))
	if err != nil {
		f.logger.Warn("failed to fetch block header", zap.Error(err))
		if apiErr, ok := errors.AsType[*api.Error](err); ok {
			// todo it might not be safe to just assume that a 404 response means that the slot has been skipped, but
			// unfortunately Lighthouse doesn't differentiate between skipped blocks and blocks not available yet.
			// We waited above for the requested block to reach the latest confirmed block, so the question here is if
			// we received the head header before from Lighthouse, can we assume that it also is able to return this one?
			if apiErr.StatusCode == http.StatusNotFound {
				f.logger.Info("received a 404, marking slot as skipped", zap.Uint64("slot", slot))
				return nil, true, nil
			}
		}
		f.logger.Error("failed to fetch block header", zap.Error(err), zap.Uint64("slot", slot))
		return nil, false, fmt.Errorf("fetching block header: %w", err)
	}

	return blockHeader, false, nil
}

func (f *HttpFetcher) fetchBlockHeader(ctx context.Context, httpClient eth2client.Service, block string) (*v1.BeaconBlockHeader, error) {
	if provider, isProvider := httpClient.(eth2client.BeaconBlockHeadersProvider); isProvider {
		blockHeaderResponse, err := provider.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return blockHeaderResponse.Data, nil
	}

	return nil, errors.New("failed to fetch block header, no BeaconBlockHeadersProvider available")
}

func (f *HttpFetcher) fetchSignedBlock(ctx context.Context, httpClient eth2client.Service, block string) (*spec.VersionedSignedBeaconBlock, error) {
	if provider, isProvider := httpClient.(eth2client.SignedBeaconBlockProvider); isProvider {
		signedBlockResponse, err := provider.SignedBeaconBlock(ctx, &api.SignedBeaconBlockOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return signedBlockResponse.Data, nil
	}

	return nil, errors.New("failed to fetch signed block, no SignedBeaconBlockProvider available")
}

func (f *HttpFetcher) fetchBlobSidecars(ctx context.Context, httpClient eth2client.Service, block string) ([]*deneb.BlobSidecar, error) {
	if provider, isProvider := httpClient.(eth2client.BlobSidecarsProvider); isProvider {
		blobSidecarResponse, err := provider.BlobSidecars(ctx, &api.BlobSidecarsOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return blobSidecarResponse.Data, nil
	}

	return nil, errors.New("failed to fetch blob sidecar, no BlobSidecarsProvider available")
}

// fetchGloasPayload returns the execution payload envelope and blobs of a Gloas block, or nil for both if the
// canonical chain did not build on the block's payload. This is decided by the next canonical block: its bid either
// builds on top of this block's payload (parent block hash equals this bid's block hash) or on the empty slot.
func (f *HttpFetcher) fetchGloasPayload(ctx context.Context, httpClient eth2client.Service, slot uint64, root phase0.Root, signedBlock *spec.VersionedSignedBeaconBlock) (*gloas.SignedExecutionPayloadEnvelope, []*deneb.Blob, error) {
	if signedBlock.Gloas == nil || signedBlock.Gloas.Message == nil || signedBlock.Gloas.Message.Body == nil ||
		signedBlock.Gloas.Message.Body.SignedExecutionPayloadBid == nil || signedBlock.Gloas.Message.Body.SignedExecutionPayloadBid.Message == nil {
		return nil, nil, fmt.Errorf("unsupported block version %s or missing execution payload bid", signedBlock.Version)
	}
	bid := signedBlock.Gloas.Message.Body.SignedExecutionPayloadBid.Message
	f.seenBidBlockHashes.Store(root.String(), bid.BlockHash)

	payloadCanonical, err := f.isGloasPayloadCanonical(ctx, httpClient, slot, root, bid)
	if err != nil {
		return nil, nil, err
	}
	if !payloadCanonical {
		f.logger.Info("execution payload of slot is not canonical, skipping envelope", zap.Uint64("slot", slot), zap.String("bid_block_hash", bid.BlockHash.String()))
		return nil, nil, nil
	}

	envelope, err := f.fetchExecutionPayloadEnvelope(ctx, httpClient, root.String())
	if err != nil {
		return nil, nil, fmt.Errorf("fetching execution payload envelope: %w", err)
	}
	if envelope.Message == nil || envelope.Message.Payload == nil {
		return nil, nil, errors.New("execution payload envelope is missing its payload")
	}
	if envelope.Message.BeaconBlockRoot != root {
		return nil, nil, fmt.Errorf("execution payload envelope is for beacon block %s, expected %s", envelope.Message.BeaconBlockRoot, root)
	}
	if envelope.Message.Payload.BlockHash != bid.BlockHash {
		return nil, nil, fmt.Errorf("execution payload block hash %s does not match the bid's block hash %s", envelope.Message.Payload.BlockHash, bid.BlockHash)
	}

	if len(bid.BlobKZGCommitments) == 0 {
		return envelope, []*deneb.Blob{}, nil
	}

	blobs, err := f.fetchBlobs(ctx, httpClient, root.String())
	if err != nil {
		if !f.isIgnorableMissingBlobsError(err) {
			f.logger.Error("failed to fetch blobs"+missingBlobsHint, zap.Error(err))
			return nil, nil, fmt.Errorf("fetching blobs: %w", err)
		}
		f.logger.Error("failed to fetch blobs, setting to empty array as --ignore-missing-blobs is set", zap.Error(err))
		return envelope, []*deneb.Blob{}, nil
	}
	if len(blobs) != len(bid.BlobKZGCommitments) {
		// a node that has pruned the blobs may also answer with an empty or partial list instead of a 404
		err := fmt.Errorf("received %d blobs for %d blob commitments", len(blobs), len(bid.BlobKZGCommitments))
		if !f.ignoreMissingBlobs {
			f.logger.Error("blobs are missing"+missingBlobsHint, zap.Error(err), zap.Uint64("slot", slot))
			return nil, nil, err
		}
		f.logger.Error("blobs are missing, setting to empty array as --ignore-missing-blobs is set", zap.Error(err), zap.Uint64("slot", slot))
		return envelope, []*deneb.Blob{}, nil
	}

	return envelope, blobs, nil
}

const missingBlobsHint = ", if the beacon node has pruned them already you need to run this using the --ignore-missing-blobs flag to ignore this error"

// isIgnorableMissingBlobsError reports whether a blob fetch error is a 404 that --ignore-missing-blobs allows to skip.
func (f *HttpFetcher) isIgnorableMissingBlobsError(err error) bool {
	var apiErr *api.Error
	return f.ignoreMissingBlobs && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// isGloasPayloadCanonical looks up the next canonical block after the given slot and checks whether its bid builds on
// top of the execution payload of the given bid. If no block exists after the given slot up to the known head (the
// head is stale, the only child got orphaned, or the spec did not announce the Gloas fork so we did not wait for the
// next slot), it waits for the head to advance instead of failing, as a failure would be retried with the same stale
// head forever.
func (f *HttpFetcher) isGloasPayloadCanonical(ctx context.Context, httpClient eth2client.Service, slot uint64, root phase0.Root, bid *gloas.ExecutionPayloadBid) (bool, error) {
	childSlot := slot + 1
	for {
		for ; childSlot <= f.latestConfirmedSlot; childSlot++ {
			child, err := f.fetchSignedBlock(ctx, httpClient, strconv.FormatUint(childSlot, 10))
			if err != nil {
				var apiErr *api.Error
				if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
					// skipped slot
					continue
				}
				return false, fmt.Errorf("fetching next block at slot %d: %w", childSlot, err)
			}

			if child.Gloas == nil || child.Gloas.Message == nil || child.Gloas.Message.Body == nil ||
				child.Gloas.Message.Body.SignedExecutionPayloadBid == nil || child.Gloas.Message.Body.SignedExecutionPayloadBid.Message == nil {
				return false, fmt.Errorf("next block at slot %d has unsupported version %s or is missing its execution payload bid", childSlot, child.Version)
			}
			if child.Gloas.Message.ParentRoot != root {
				return false, fmt.Errorf("next block at slot %d has parent root %s, expected %s", childSlot, child.Gloas.Message.ParentRoot, root)
			}

			return child.Gloas.Message.Body.SignedExecutionPayloadBid.Message.ParentBlockHash == bid.BlockHash, nil
		}

		f.logger.Info("no block after slot up to head slot yet, waiting for the head to advance before deciding whether its execution payload is canonical", zap.Uint64("slot", slot), zap.Uint64("latest_confirmed_slot", f.latestConfirmedSlot))
		if err := f.waitForHeadSlot(ctx, httpClient, f.latestConfirmedSlot+1); err != nil {
			return false, fmt.Errorf("waiting for a block after slot %d: %w", slot, err)
		}
	}
}

// gloasParentBlockID derives the Firehose block ID of a Gloas block's parent. Whether the parent's execution payload
// became canonical is told by this block's bid: it builds on the parent's bid block hash if the parent's payload was
// included, and on an earlier execution block otherwise. The parent of the first Gloas block is a pre-Gloas block whose
// ID is just its root.
func (f *HttpFetcher) gloasParentBlockID(ctx context.Context, httpClient eth2client.Service, block *gloas.BeaconBlock) (string, error) {
	parentRoot := block.ParentRoot

	var parentBidBlockHash phase0.Hash32
	if cached, ok := f.seenBidBlockHashes.Load(parentRoot.String()); ok {
		parentBidBlockHash = cached.(phase0.Hash32)
	} else {
		f.logger.Debug("missing parent bid block hash in our buffer, requesting parent block from the beacon node", zap.Uint64("slot", uint64(block.Slot)), zap.String("parent_root", parentRoot.String()))
		parent, err := f.fetchSignedBlock(ctx, httpClient, parentRoot.String())
		if err != nil {
			return "", fmt.Errorf("fetching parent block %s: %w", parentRoot, err)
		}
		if parent.Version < spec.DataVersionGloas {
			return parentRoot.String(), nil
		}
		if parent.Gloas == nil || parent.Gloas.Message == nil || parent.Gloas.Message.Body == nil ||
			parent.Gloas.Message.Body.SignedExecutionPayloadBid == nil || parent.Gloas.Message.Body.SignedExecutionPayloadBid.Message == nil {
			return "", fmt.Errorf("parent block %s is missing its execution payload bid", parentRoot)
		}
		parentBidBlockHash = parent.Gloas.Message.Body.SignedExecutionPayloadBid.Message.BlockHash
		f.seenBidBlockHashes.Store(parentRoot.String(), parentBidBlockHash)
	}

	parentPayloadCanonical := block.Body.SignedExecutionPayloadBid.Message.ParentBlockHash == parentBidBlockHash
	return gloasBlockID(parentRoot, parentPayloadCanonical), nil
}

func (f *HttpFetcher) fetchExecutionPayloadEnvelope(ctx context.Context, httpClient eth2client.Service, block string) (*gloas.SignedExecutionPayloadEnvelope, error) {
	if provider, isProvider := httpClient.(eth2client.ExecutionPayloadProvider); isProvider {
		envelopeResponse, err := provider.SignedExecutionPayloadEnvelope(ctx, &api.SignedExecutionPayloadEnvelopeOpts{Block: block})
		if err != nil {
			return nil, err
		}
		if envelopeResponse.Data == nil || envelopeResponse.Data.Gloas == nil {
			return nil, errors.New("empty execution payload envelope response")
		}

		return envelopeResponse.Data.Gloas, nil
	}

	return nil, errors.New("failed to fetch execution payload envelope, no ExecutionPayloadProvider available")
}

func (f *HttpFetcher) fetchBlobs(ctx context.Context, httpClient eth2client.Service, block string) ([]*deneb.Blob, error) {
	if provider, isProvider := httpClient.(eth2client.BlobsProvider); isProvider {
		blobsResponse, err := provider.Blobs(ctx, &api.BlobsOpts{Block: block})
		if err != nil {
			return nil, err
		}

		return blobsResponse.Data, nil
	}

	return nil, errors.New("failed to fetch blobs, no BlobsProvider available")
}

func (f *HttpFetcher) fetchSpec(ctx context.Context, httpClient eth2client.Service) (map[string]any, error) {
	if provider, isProvider := httpClient.(eth2client.SpecProvider); isProvider {
		specResponse, err := provider.Spec(ctx, &api.SpecOpts{})
		if err != nil {
			return nil, err
		}

		return specResponse.Data, nil
	}

	return nil, errors.New("failed to fetch spec, no SpecProvider available")
}

func (f *HttpFetcher) fetchGenesis(ctx context.Context, httpClient eth2client.Service) (*v1.Genesis, error) {
	if provider, isProvider := httpClient.(eth2client.GenesisProvider); isProvider {
		genesisResponse, err := provider.Genesis(ctx, &api.GenesisOpts{})
		if err != nil {
			return nil, err
		}

		return genesisResponse.Data, nil
	}

	return nil, errors.New("failed to fetch genesis, no GenesisProvider available")
}
