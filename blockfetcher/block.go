package blockfetcher

import (
	pbbeacon "firehose-beacon/pb/sf/beacon/type/v1"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"google.golang.org/protobuf/types/known/anypb"
)

func toBlock(slot, parentSlot, finalizedSlot uint64, header *v1.BeaconBlockHeader, signedBlock *spec.VersionedSignedBeaconBlock, blobSidecars []*deneb.BlobSidecar) (*pbbstream.Block, error) {

	libNum := finalizedSlot
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

		Blobs: blobsToProto(blobSidecars),
	}

	anyBlock, err := anypb.New(beaconBlock)
	if err != nil {
		return nil, err
	}

	res := &pbbstream.Block{
		Number:   slot,
		Id:       header.Root.String(),
		ParentId: parentRoot.String(),
		// Timestamp: todo figure out where to get from non deneb specs
		LibNum:    libNum,
		ParentNum: parentSlot,
		Payload:   anyBlock,
	}

	return res, nil
}

func blobsToProto(blobSidecars []*deneb.BlobSidecar) []*pbbeacon.Blob {

	res := make([]*pbbeacon.Blob, 0, len(blobSidecars))
	for _, b := range blobSidecars {
		res = append(res, &pbbeacon.Blob{
			Index:         uint64(b.Index),
			Blob:          b.Blob[:],
			KzgCommitment: b.KZGCommitment.String(),
			KzgProof:      b.KZGProof.String(),
			// todo KzgCommitmentInclusionProof:,
		})
	}

	return res
}
