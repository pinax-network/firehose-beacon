package blockfetcher

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	pbbeacon "github.com/pinax-network/firehose-beacon/pb/sf/beacon/type/v1"
	"github.com/rs/zerolog"
	"go.uber.org/zap/zaptest"
)

// TestGloasFetchAgainstBeaconNode fetches the most recent slots from a beacon node past the Gloas fork and checks the
// produced Firehose blocks. Set FIREBEACON_GLOAS_BEACON_URL to run it, e.g. a Glamsterdam devnet beacon API.
// FIREBEACON_GLOAS_SLOTS sets the number of slots (default 32) and FIREBEACON_GLOAS_START_SLOT the first one (default
// head minus the number of slots).
func TestGloasFetchAgainstBeaconNode(t *testing.T) {
	url := os.Getenv("FIREBEACON_GLOAS_BEACON_URL")
	if url == "" {
		t.Skip("FIREBEACON_GLOAS_BEACON_URL not set")
	}
	slots := uint64(32)
	if v := os.Getenv("FIREBEACON_GLOAS_SLOTS"); v != "" {
		var err error
		if slots, err = strconv.ParseUint(v, 10, 64); err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	client, err := http.New(ctx, http.WithAddress(url), http.WithTimeout(60*time.Second), http.WithLogLevel(zerolog.WarnLevel))
	if err != nil {
		t.Fatal(err)
	}

	f, err := NewHttp(client, 0, time.Second, false, zaptest.NewLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	if f.gloasForkSlot == 0 || f.blockTime == 0 {
		t.Fatalf("unexpected fork slot %d / block time %d", f.gloasForkSlot, f.blockTime)
	}

	head, err := f.fetchBlockHeader(ctx, client, HeadBlock)
	if err != nil {
		t.Fatal(err)
	}
	headSlot := uint64(head.Header.Message.Slot)
	if headSlot < f.gloasForkSlot+slots+1 {
		t.Fatalf("head slot %d is not far enough past the gloas fork slot %d", headSlot, f.gloasForkSlot)
	}

	startSlot := headSlot - slots
	if v := os.Getenv("FIREBEACON_GLOAS_START_SLOT"); v != "" {
		if startSlot, err = strconv.ParseUint(v, 10, 64); err != nil {
			t.Fatal(err)
		}
		if startSlot < f.gloasForkSlot || startSlot+slots >= headSlot {
			t.Fatalf("start slot %d out of range", startSlot)
		}
	}

	var withPayload, withoutPayload, skipped, blobs int
	var previous *pbbeacon.Block
	previousID := ""
	for slot := startSlot; slot < startSlot+slots; slot++ {
		block, skip, err := f.Fetch(ctx, client, slot)
		if err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		if skip {
			skipped++
			continue
		}

		beaconBlock := &pbbeacon.Block{}
		if err := block.Payload.UnmarshalTo(beaconBlock); err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
		if beaconBlock.Spec != pbbeacon.Spec_GLOAS || beaconBlock.Slot != slot || block.Number != slot {
			t.Fatalf("slot %d: unexpected spec %s / slot %d / number %d", slot, beaconBlock.Spec, beaconBlock.Slot, block.Number)
		}
		body := beaconBlock.GetGloas()
		if body == nil || body.SignedExecutionPayloadBid == nil {
			t.Fatalf("slot %d: missing gloas body or bid", slot)
		}
		bid := body.SignedExecutionPayloadBid.Message

		// the payload status of the previous block is decided by this block's bid, and the block IDs encode it
		if previous != nil && previous.Slot == beaconBlock.ParentSlot {
			prevBody := previous.GetGloas()
			builtOnPayload := bytes.Equal(bid.ParentBlockHash, prevBody.SignedExecutionPayloadBid.Message.BlockHash)
			if builtOnPayload != (prevBody.ExecutionPayloadEnvelope != nil) {
				t.Fatalf("slot %d: payload present %t, but next block builds on it %t", previous.Slot, prevBody.ExecutionPayloadEnvelope != nil, builtOnPayload)
			}
			if block.ParentId != previousID {
				t.Fatalf("slot %d: parent id %s differs from the previous block id %s", slot, block.ParentId, previousID)
			}
		}
		if expectedID := gloasBlockID(phase0.Root(beaconBlock.Root), body.ExecutionPayloadEnvelope != nil); block.Id != expectedID {
			t.Fatalf("slot %d: block id %s, expected %s", slot, block.Id, expectedID)
		}

		if body.ExecutionPayloadEnvelope == nil {
			withoutPayload++
			if len(body.EmbeddedBlobs) != 0 {
				t.Fatalf("slot %d: blobs embedded without a payload", slot)
			}
		} else {
			withPayload++
			payload := body.ExecutionPayloadEnvelope.Message.Payload
			if !bytes.Equal(payload.BlockHash, bid.BlockHash) {
				t.Fatalf("slot %d: payload block hash differs from bid", slot)
			}
			if !payload.Timestamp.AsTime().Equal(beaconBlock.Timestamp.AsTime()) {
				t.Fatalf("slot %d: block timestamp %s differs from payload timestamp %s", slot, beaconBlock.Timestamp.AsTime(), payload.Timestamp.AsTime())
			}
			if payload.SlotNumber != slot {
				t.Fatalf("slot %d: payload slot number %d", slot, payload.SlotNumber)
			}
			if len(body.EmbeddedBlobs) != len(bid.BlobKzgCommitments) {
				t.Fatalf("slot %d: %d blobs for %d commitments", slot, len(body.EmbeddedBlobs), len(bid.BlobKzgCommitments))
			}
			for i, b := range body.EmbeddedBlobs {
				if len(b.Blob) != 131072 || !bytes.Equal(b.KzgCommitment, bid.BlobKzgCommitments[i]) {
					t.Fatalf("slot %d: blob %d malformed", slot, i)
				}
			}
			blobs += len(body.EmbeddedBlobs)
		}
		previous = beaconBlock
		previousID = block.Id
	}

	t.Logf("fetched %d slots: %d with payload, %d without payload, %d skipped, %d blobs", slots, withPayload, withoutPayload, skipped, blobs)
	if withPayload == 0 {
		t.Fatal("no block with an execution payload")
	}
}

func TestRequiredHeadSlot(t *testing.T) {
	f := &HttpFetcher{gloasForkSlot: 100}
	for _, c := range []struct{ requested, expected uint64 }{{0, 0}, {99, 99}, {100, 101}, {200, 201}} {
		if got := f.requiredHeadSlot(c.requested); got != c.expected {
			t.Errorf("requiredHeadSlot(%d) = %d, expected %d", c.requested, got, c.expected)
		}
	}
}

func TestIsGloasPayloadCanonicalWithoutNextBlock(t *testing.T) {
	// without a later block up to the known head, the check refreshes the head instead of failing; with no client
	// available the head refresh is what fails here
	f := &HttpFetcher{latestConfirmedSlot: 10, logger: zaptest.NewLogger(t)}
	_, err := f.isGloasPayloadCanonical(context.Background(), nil, 10, [32]byte{}, nil)
	if err == nil || !strings.Contains(err.Error(), "waiting for a block after slot 10") {
		t.Fatalf("expected a head refresh error when no later block exists, got %v", err)
	}
}

func TestGloasBlockID(t *testing.T) {
	root := phase0.Root{1, 2, 3}
	full := gloasBlockID(root, true)
	empty := gloasBlockID(root, false)
	if full != root.String() {
		t.Errorf("block id with payload %s, expected the root %s", full, root)
	}
	if empty == full || len(empty) != len(full) || !strings.HasPrefix(empty, "0x") {
		t.Errorf("block id without payload %s should differ from the root but keep its format", empty)
	}
	if gloasBlockID(root, false) != empty || gloasBlockID(phase0.Root{4}, false) == empty {
		t.Error("block id without payload should be deterministic and depend on the root")
	}
}
