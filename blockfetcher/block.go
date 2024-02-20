package blockfetcher

import (
	pbbeacon "firehose-beacon/pb/sf/beacon/type/v1"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

func toBlock(slot, finalizedSlot uint64, header *v1.BeaconBlockHeader, signedBlock *deneb.BeaconBlock, blobSidecars []*deneb.BlobSidecar) (*pbbstream.Block, error) {

	libNum := finalizedSlot
	if finalizedSlot > slot {
		panic("got a finalizedSlot > slot")
	}

	beaconBlock := &pbbeacon.Block{
		Slot:          slot,
		ProposerIndex: uint64(signedBlock.ProposerIndex),
		ParentRoot:    signedBlock.ParentRoot.String(),
		StateRoot:     signedBlock.StateRoot.String(),
	}

	anyBlock, err := anypb.New(beaconBlock)
	if err != nil {
		return nil, err
	}

	res := &pbbstream.Block{
		Number:    slot,
		Id:        header.Root.String(),
		ParentId:  signedBlock.ParentRoot.String(),
		Timestamp: timestamppb.New(time.Unix(int64(signedBlock.Body.ExecutionPayload.Timestamp), 0)),
		LibNum:    libNum,
		Payload:   anyBlock,
	}

	// todo this doesn't work if we have skip-able blocks
	if res.Number > 0 {
		res.ParentNum = res.Number - 1
	}

	return res, nil
}
