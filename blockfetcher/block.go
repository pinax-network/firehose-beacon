package blockfetcher

import (
	pbbeacon "firehose-beacon/pb/sf/beacon/type/v1"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"google.golang.org/protobuf/types/known/anypb"
)

func toBlock(slot, finalizedSlot uint64, header *v1.BeaconBlockHeader, signedBlock *spec.VersionedSignedBeaconBlock, blobSidecars []*deneb.BlobSidecar) (*pbbstream.Block, error) {

	libNum := finalizedSlot

	// todo this doesn't work if we have skip-able blocks
	parentSlot := slot
	if parentSlot > 0 {
		parentSlot -= 1
	}

	if finalizedSlot > slot {
		libNum = parentSlot
	}

	proposerIndex, err := signedBlock.ProposerIndex()
	if err != nil {
		return nil, err
	}
	parentRoot, err := signedBlock.ParentRoot()
	if err != nil {
		return nil, err
	}
	stateRoot, err := signedBlock.StateRoot()
	if err != nil {
		return nil, err
	}

	beaconBlock := &pbbeacon.Block{
		Slot:          slot,
		ProposerIndex: uint64(proposerIndex),
		ParentRoot:    parentRoot.String(),
		StateRoot:     stateRoot.String(),
	}

	anyBlock, err := anypb.New(beaconBlock)
	if err != nil {
		return nil, err
	}

	res := &pbbstream.Block{
		Number:   slot,
		Id:       header.Root.String(),
		ParentId: parentRoot.String(),
		// Timestamp: timestamppb.New(time.Unix(int64(signedBlock.Body.ExecutionPayload.Timestamp), 0)),
		LibNum:    libNum,
		ParentNum: parentSlot,
		Payload:   anyBlock,
	}

	return res, nil
}
