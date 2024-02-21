package blockfetcher

import (
	pbbeacon "firehose-beacon/pb/sf/beacon/type/v1"
	"fmt"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"google.golang.org/protobuf/types/known/anypb"
)

func toBlock(slot, parentSlot, finalizedSlot uint64, root string, header *v1.BeaconBlockHeader, signedBlock *spec.VersionedSignedBeaconBlock, blobSidecars []*deneb.BlobSidecar) (*pbbstream.Block, error) {

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
		ParentSlot:    parentSlot,
		Root:          root,
		ParentRoot:    parentRoot.String(),
		StateRoot:     stateRoot.String(),
		ProposerIndex: uint64(proposerIndex),
	}

	switch signedBlock.Version {
	//case spec.DataVersionPhase0:
	//	beaconBlock.Body = &pbbeacon.Block_Phase0{Phase0: toPhase0Body(signedBlock.Phase0)}
	case spec.DataVersionDeneb:
		beaconBlock.Spec = pbbeacon.Spec_DENEB
		beaconBlock.Body = &pbbeacon.Block_Deneb{Deneb: toDenebBody(signedBlock.Deneb, blobSidecars)}
	default:
		return nil, fmt.Errorf("unknown spec: %q", signedBlock.String())
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

func toDenebBody(signedBlock *deneb.SignedBeaconBlock, blobSidecars []*deneb.BlobSidecar) *pbbeacon.DenebBody {

	blockBody := signedBlock.Message.Body
	return &pbbeacon.DenebBody{
		RandoReveal:       blockBody.RANDAOReveal.String(),
		Eth1Data:          eth1DataToProto(blockBody.ETH1Data),
		Graffiti:          fmt.Sprintf("%#x", blockBody.Graffiti),
		ProposerSlashings: proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings: attesterSlashingsToProto(blockBody.AttesterSlashings),
	}
}

//func bodyToProto(signedBlock *spec.VersionedSignedBeaconBlock) *pbbeacon.Body {
//
//	res := &pbbeacon.Body{}
//
//	if randoReveal, err := signedBlock.RandaoReveal(); err == nil {
//		res.RandoReveal = randoReveal.String()
//	}
//	if eth1Data, err := signedBlock.ETH1Data(); err == nil {
//		res.Eth1Data = eth1DataToProto(eth1Data)
//	}
//	if graffiti, err := signedBlock.Graffiti(); err == nil {
//		res.Graffiti = fmt.Sprintf("%#x", graffiti)
//	}
//
//	proposerSlashings, err := signedBlock.ProposerSlashings()
//
//	attesterSlashings, err := signedBlock.AttesterSlashings()
//
//	attestations, err := signedBlock.Attestations()
//
//	deposits, err := signedBlock.Deposits()
//
//	voluntaryExits, err := signedBlock.VoluntaryExits()
//
//	syncAggregate, err := signedBlock.SyncAggregate()
//
//	blsToExecutionChanges, err := signedBlock.BLSToExecutionChanges()
//
//	blobKzgCommitments, err := signedBlock.BlobKZGCommitments()
//
//	if signedBlock.Deneb != nil {
//
//		signedBlock.Deneb.Message.Body.ExecutionPayload
//
//	} else if signedBlock.Capella != nil {
//
//		signedBlock.Capella.Message.Body.ExecutionPayload
//	}
//
//	return res
//}

func eth1DataToProto(eth1Data *phase0.ETH1Data) *pbbeacon.Eth1Data {
	return &pbbeacon.Eth1Data{
		DepositRoot:  eth1Data.DepositRoot.String(),
		DepositCount: eth1Data.DepositCount,
		BlockHash:    fmt.Sprintf("%#x", eth1Data.BlockHash),
	}
}

func proposerSlashingsToProto(proposerSlashings []*phase0.ProposerSlashing) []*pbbeacon.ProposerSlashing {
	res := make([]*pbbeacon.ProposerSlashing, 0, len(proposerSlashings))
	for _, s := range proposerSlashings {
		res = append(res, &pbbeacon.ProposerSlashing{
			SignedHeader_1: signedBeaconBlockHeaderToProto(s.SignedHeader1),
			SignedHeader_2: signedBeaconBlockHeaderToProto(s.SignedHeader2),
		})
	}
	return res
}

func signedBeaconBlockHeaderToProto(signedBeaconBlockHeader *phase0.SignedBeaconBlockHeader) *pbbeacon.SignedBeaconBlockHeader {
	return &pbbeacon.SignedBeaconBlockHeader{
		Message:   beaconBlockHeaderToProto(signedBeaconBlockHeader.Message),
		Signature: signedBeaconBlockHeader.Signature.String(),
	}
}

func beaconBlockHeaderToProto(beaconBlockHeader *phase0.BeaconBlockHeader) *pbbeacon.BeaconBlockHeader {
	return &pbbeacon.BeaconBlockHeader{
		Slot:          uint64(beaconBlockHeader.Slot),
		ProposerIndex: uint64(beaconBlockHeader.ProposerIndex),
		ParentRoot:    beaconBlockHeader.ParentRoot.String(),
		StateRoot:     beaconBlockHeader.StateRoot.String(),
		BodyRoot:      beaconBlockHeader.BodyRoot.String(),
	}
}

func attesterSlashingsToProto(attesterSlashings []*phase0.AttesterSlashing) []*pbbeacon.AttesterSlashing {
	res := make([]*pbbeacon.AttesterSlashing, 0, len(attesterSlashings))
	for _, a := range attesterSlashings {
		res = append(res, &pbbeacon.AttesterSlashing{
			Attestation_1: indexedAttestationToProto(a.Attestation1),
			Attestation_2: indexedAttestationToProto(a.Attestation2),
		})
	}
	return res
}

func indexedAttestationToProto(indexedAttestation *phase0.IndexedAttestation) *pbbeacon.IndexedAttestation {
	return &pbbeacon.IndexedAttestation{
		AttestingIndices: indexedAttestation.AttestingIndices,
		Data:             attestationDataToProto(indexedAttestation.Data),
		Signature:        indexedAttestation.Signature.String(),
	}
}

func attestationDataToProto(attestationData *phase0.AttestationData) *pbbeacon.AttestationData {
	return &pbbeacon.AttestationData{
		Slot:            uint64(attestationData.Slot),
		CommitteeIndex:  uint64(attestationData.Index),
		BeaconBlockRoot: attestationData.BeaconBlockRoot.String(),
		Source:          checkpointToProto(attestationData.Source),
		Target:          checkpointToProto(attestationData.Target),
	}
}

func checkpointToProto(checkpoint *phase0.Checkpoint) *pbbeacon.Checkpoint {
	return &pbbeacon.Checkpoint{
		Epoch: uint64(checkpoint.Epoch),
		Root:  checkpoint.Root.String(),
	}
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

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
