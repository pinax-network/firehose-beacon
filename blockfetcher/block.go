package blockfetcher

import (
	"fmt"
	v1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	pbbeacon "github.com/pinax-network/firehose-beacon/pb/sf/beacon/type/v1"
	pbbstream "github.com/streamingfast/bstream/pb/sf/bstream/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
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
		Version:       1,
		Slot:          slot,
		ParentSlot:    parentSlot,
		Root:          header.Root[:],
		ParentRoot:    parentRoot[:],
		StateRoot:     stateRoot[:],
		ProposerIndex: uint64(proposerIndex),
	}

	switch signedBlock.Version {
	case spec.DataVersionPhase0:
		beaconBlock.Spec = pbbeacon.Spec_PHASE0
		beaconBlock.Body = &pbbeacon.Block_Phase0{Phase0: toPhase0Body(signedBlock.Phase0)}
		beaconBlock.Signature = signedBlock.Phase0.Signature[:]
	case spec.DataVersionAltair:
		beaconBlock.Spec = pbbeacon.Spec_ALTAIR
		beaconBlock.Body = &pbbeacon.Block_Altair{Altair: toAltairBody(signedBlock.Altair)}
		beaconBlock.Signature = signedBlock.Altair.Signature[:]
	case spec.DataVersionBellatrix:
		beaconBlock.Spec = pbbeacon.Spec_BELLATRIX
		beaconBlock.Body = &pbbeacon.Block_Bellatrix{Bellatrix: toBellatrixBody(signedBlock.Bellatrix)}
		beaconBlock.Signature = signedBlock.Bellatrix.Signature[:]
		beaconBlock.Timestamp = beaconBlock.GetBellatrix().ExecutionPayload.Timestamp
	case spec.DataVersionCapella:
		beaconBlock.Spec = pbbeacon.Spec_CAPELLA
		beaconBlock.Body = &pbbeacon.Block_Capella{Capella: toCapellaBody(signedBlock.Capella)}
		beaconBlock.Signature = signedBlock.Capella.Signature[:]
		beaconBlock.Timestamp = beaconBlock.GetCapella().ExecutionPayload.Timestamp
	case spec.DataVersionDeneb:
		beaconBlock.Spec = pbbeacon.Spec_DENEB
		beaconBlock.Body = &pbbeacon.Block_Deneb{Deneb: toDenebBody(signedBlock.Deneb, blobSidecars)}
		beaconBlock.Signature = signedBlock.Deneb.Signature[:]
		beaconBlock.Timestamp = beaconBlock.GetDeneb().ExecutionPayload.Timestamp
	default:
		return nil, fmt.Errorf("unimplemented spec: %q", signedBlock.String())
	}

	anyBlock, err := anypb.New(beaconBlock)
	if err != nil {
		return nil, err
	}

	res := &pbbstream.Block{
		Number:   slot,
		Id:       header.Root.String(),
		ParentId: parentRoot.String(),
		// todo figure out where to get the timestamp from non deneb specs
		Timestamp: beaconBlock.Timestamp,
		LibNum:    libNum,
		ParentNum: parentSlot,
		Payload:   anyBlock,
	}

	return res, nil
}

func toPhase0Body(signedBlock *phase0.SignedBeaconBlock) *pbbeacon.Phase0Body {
	blockBody := signedBlock.Message.Body
	return &pbbeacon.Phase0Body{
		RandoReveal:       blockBody.RANDAOReveal[:],
		Eth1Data:          eth1DataToProto(blockBody.ETH1Data),
		Graffiti:          blockBody.Graffiti[:],
		ProposerSlashings: proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings: attesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:      attestationsToProto(blockBody.Attestations),
		Deposits:          depositsToProto(blockBody.Deposits),
		VoluntaryExits:    voluntaryExitsToProto(blockBody.VoluntaryExits),
	}
}

func toAltairBody(signedBlock *altair.SignedBeaconBlock) *pbbeacon.AltairBody {
	blockBody := signedBlock.Message.Body
	return &pbbeacon.AltairBody{
		RandoReveal:       blockBody.RANDAOReveal[:],
		Eth1Data:          eth1DataToProto(blockBody.ETH1Data),
		Graffiti:          blockBody.Graffiti[:],
		ProposerSlashings: proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings: attesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:      attestationsToProto(blockBody.Attestations),
		Deposits:          depositsToProto(blockBody.Deposits),
		VoluntaryExits:    voluntaryExitsToProto(blockBody.VoluntaryExits),
		SyncAggregate:     syncAggregateToProto(blockBody.SyncAggregate),
	}
}

func toBellatrixBody(signedBlock *bellatrix.SignedBeaconBlock) *pbbeacon.BellatrixBody {
	blockBody := signedBlock.Message.Body
	return &pbbeacon.BellatrixBody{
		RandoReveal:       blockBody.RANDAOReveal[:],
		Eth1Data:          eth1DataToProto(blockBody.ETH1Data),
		Graffiti:          blockBody.Graffiti[:],
		ProposerSlashings: proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings: attesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:      attestationsToProto(blockBody.Attestations),
		Deposits:          depositsToProto(blockBody.Deposits),
		VoluntaryExits:    voluntaryExitsToProto(blockBody.VoluntaryExits),
		SyncAggregate:     syncAggregateToProto(blockBody.SyncAggregate),
		ExecutionPayload:  bellatrixExecutionPayloadToProto(blockBody.ExecutionPayload),
	}
}

func toCapellaBody(signedBlock *capella.SignedBeaconBlock) *pbbeacon.CapellaBody {
	blockBody := signedBlock.Message.Body
	return &pbbeacon.CapellaBody{
		RandoReveal:       blockBody.RANDAOReveal[:],
		Eth1Data:          eth1DataToProto(blockBody.ETH1Data),
		Graffiti:          blockBody.Graffiti[:],
		ProposerSlashings: proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings: attesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:      attestationsToProto(blockBody.Attestations),
		Deposits:          depositsToProto(blockBody.Deposits),
		VoluntaryExits:    voluntaryExitsToProto(blockBody.VoluntaryExits),
		SyncAggregate:     syncAggregateToProto(blockBody.SyncAggregate),
		ExecutionPayload:  capellaExecutionPayloadToProto(blockBody.ExecutionPayload),
	}
}

func toDenebBody(signedBlock *deneb.SignedBeaconBlock, blobSidecars []*deneb.BlobSidecar) *pbbeacon.DenebBody {
	blockBody := signedBlock.Message.Body
	return &pbbeacon.DenebBody{
		RandoReveal:           blockBody.RANDAOReveal[:],
		Eth1Data:              eth1DataToProto(blockBody.ETH1Data),
		Graffiti:              blockBody.Graffiti[:],
		ProposerSlashings:     proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings:     attesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:          attestationsToProto(blockBody.Attestations),
		Deposits:              depositsToProto(blockBody.Deposits),
		VoluntaryExits:        voluntaryExitsToProto(blockBody.VoluntaryExits),
		SyncAggregate:         syncAggregateToProto(blockBody.SyncAggregate),
		ExecutionPayload:      denebExecutionPayloadToProto(blockBody.ExecutionPayload),
		BlsToExecutionChanges: signedBlsToExecutionChangeToProto(blockBody.BLSToExecutionChanges),
		BlobKzgCommitments:    kzgCommitmentsToProto(blockBody.BlobKZGCommitments),

		EmbeddedBlobs: blobsToProto(blobSidecars),
	}
}

func eth1DataToProto(eth1Data *phase0.ETH1Data) *pbbeacon.Eth1Data {
	return &pbbeacon.Eth1Data{
		DepositRoot:  eth1Data.DepositRoot[:],
		DepositCount: eth1Data.DepositCount,
		BlockHash:    eth1Data.BlockHash,
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
		Signature: signedBeaconBlockHeader.Signature[:],
	}
}

func beaconBlockHeaderToProto(beaconBlockHeader *phase0.BeaconBlockHeader) *pbbeacon.BeaconBlockHeader {
	return &pbbeacon.BeaconBlockHeader{
		Slot:          uint64(beaconBlockHeader.Slot),
		ProposerIndex: uint64(beaconBlockHeader.ProposerIndex),
		ParentRoot:    beaconBlockHeader.ParentRoot[:],
		StateRoot:     beaconBlockHeader.StateRoot[:],
		BodyRoot:      beaconBlockHeader.BodyRoot[:],
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
		Signature:        indexedAttestation.Signature[:],
	}
}

func attestationDataToProto(attestationData *phase0.AttestationData) *pbbeacon.AttestationData {
	return &pbbeacon.AttestationData{
		Slot:            uint64(attestationData.Slot),
		CommitteeIndex:  uint64(attestationData.Index),
		BeaconBlockRoot: attestationData.BeaconBlockRoot[:],
		Source:          checkpointToProto(attestationData.Source),
		Target:          checkpointToProto(attestationData.Target),
	}
}

func checkpointToProto(checkpoint *phase0.Checkpoint) *pbbeacon.Checkpoint {
	return &pbbeacon.Checkpoint{
		Epoch: uint64(checkpoint.Epoch),
		Root:  checkpoint.Root[:],
	}
}

func attestationsToProto(attestations []*phase0.Attestation) []*pbbeacon.Attestation {
	res := make([]*pbbeacon.Attestation, 0, len(attestations))
	for _, a := range attestations {
		res = append(res, &pbbeacon.Attestation{
			AggregationBits: a.AggregationBits,
			Data:            attestationDataToProto(a.Data),
			Signature:       a.Signature[:],
		})
	}
	return res
}

func depositsToProto(deposits []*phase0.Deposit) []*pbbeacon.Deposit {
	res := make([]*pbbeacon.Deposit, 0, len(deposits))
	for _, d := range deposits {
		res = append(res, &pbbeacon.Deposit{
			Proof: d.Proof,
			Data:  depositDataToProto(d.Data),
		})
	}
	return res
}

func depositDataToProto(depositData *phase0.DepositData) *pbbeacon.DepositData {
	return &pbbeacon.DepositData{
		PublicKey:             depositData.PublicKey[:],
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Gwei:                  uint64(depositData.Amount),
		Signature:             depositData.Signature[:],
	}
}

func voluntaryExitsToProto(voluntaryExits []*phase0.SignedVoluntaryExit) []*pbbeacon.SignedVoluntaryExit {
	res := make([]*pbbeacon.SignedVoluntaryExit, 0, len(voluntaryExits))
	for _, v := range voluntaryExits {
		res = append(res, &pbbeacon.SignedVoluntaryExit{
			Message:   voluntaryExitToProto(v.Message),
			Signature: v.Signature[:],
		})
	}
	return res
}

func voluntaryExitToProto(voluntaryExit *phase0.VoluntaryExit) *pbbeacon.VoluntaryExit {
	return &pbbeacon.VoluntaryExit{
		Epoch:          uint64(voluntaryExit.Epoch),
		ValidatorIndex: uint64(voluntaryExit.ValidatorIndex),
	}
}

func syncAggregateToProto(syncAggregate *altair.SyncAggregate) *pbbeacon.SyncAggregate {
	return &pbbeacon.SyncAggregate{
		SyncCommiteeBits:      syncAggregate.SyncCommitteeBits,
		SyncComitteeSignature: syncAggregate.SyncCommitteeSignature[:],
	}
}

func bellatrixExecutionPayloadToProto(executionPayload *bellatrix.ExecutionPayload) *pbbeacon.BellatrixExecutionPayload {
	return &pbbeacon.BellatrixExecutionPayload{
		ParentHash:    executionPayload.ParentHash[:],
		FeeRecipient:  executionPayload.FeeRecipient[:],
		StateRoot:     executionPayload.StateRoot[:],
		ReceiptsRoot:  executionPayload.ReceiptsRoot[:],
		LogsBloom:     executionPayload.LogsBloom[:],
		PrevRandao:    executionPayload.PrevRandao[:],
		BlockNumber:   executionPayload.BlockNumber,
		GasLimit:      executionPayload.GasLimit,
		GasUsed:       executionPayload.GasUsed,
		Timestamp:     timestamppb.New(time.Unix(int64(executionPayload.Timestamp), 0)),
		ExtraData:     executionPayload.ExtraData[:],
		BaseFeePerGas: executionPayload.BaseFeePerGas[:],
		BlockHash:     executionPayload.BlockHash[:],
		Transactions:  transactionsToProto(executionPayload.Transactions),
	}
}

func capellaExecutionPayloadToProto(executionPayload *capella.ExecutionPayload) *pbbeacon.CapellaExecutionPayload {
	return &pbbeacon.CapellaExecutionPayload{
		ParentHash:    executionPayload.ParentHash[:],
		FeeRecipient:  executionPayload.FeeRecipient[:],
		StateRoot:     executionPayload.StateRoot[:],
		ReceiptsRoot:  executionPayload.ReceiptsRoot[:],
		LogsBloom:     executionPayload.LogsBloom[:],
		PrevRandao:    executionPayload.PrevRandao[:],
		BlockNumber:   executionPayload.BlockNumber,
		GasLimit:      executionPayload.GasLimit,
		GasUsed:       executionPayload.GasUsed,
		Timestamp:     timestamppb.New(time.Unix(int64(executionPayload.Timestamp), 0)),
		ExtraData:     executionPayload.ExtraData[:],
		BaseFeePerGas: executionPayload.BaseFeePerGas[:],
		BlockHash:     executionPayload.BlockHash[:],
		Transactions:  transactionsToProto(executionPayload.Transactions),
		Withdrawals:   withdrawalsToProto(executionPayload.Withdrawals),
	}
}

func denebExecutionPayloadToProto(executionPayload *deneb.ExecutionPayload) *pbbeacon.DenebExecutionPayload {
	return &pbbeacon.DenebExecutionPayload{
		ParentHash:    executionPayload.ParentHash[:],
		FeeRecipient:  executionPayload.FeeRecipient[:],
		StateRoot:     executionPayload.StateRoot[:],
		ReceiptsRoot:  executionPayload.ReceiptsRoot[:],
		LogsBloom:     executionPayload.LogsBloom[:],
		PrevRandao:    executionPayload.PrevRandao[:],
		BlockNumber:   executionPayload.BlockNumber,
		GasLimit:      executionPayload.GasLimit,
		GasUsed:       executionPayload.GasUsed,
		Timestamp:     timestamppb.New(time.Unix(int64(executionPayload.Timestamp), 0)),
		ExtraData:     executionPayload.ExtraData[:],
		BaseFeePerGas: executionPayload.BaseFeePerGas.Bytes(),
		BlockHash:     executionPayload.BlockHash[:],
		Transactions:  transactionsToProto(executionPayload.Transactions),
		Withdrawals:   withdrawalsToProto(executionPayload.Withdrawals),
		BlobGasUsed:   executionPayload.BlobGasUsed,
		ExcessBlobGas: executionPayload.ExcessBlobGas,
	}
}

func transactionsToProto(transactions []bellatrix.Transaction) [][]byte {
	res := make([][]byte, 0, len(transactions))
	for _, t := range transactions {
		res = append(res, t)
	}
	return res
}

func withdrawalsToProto(withdrawals []*capella.Withdrawal) []*pbbeacon.Withdrawal {
	res := make([]*pbbeacon.Withdrawal, 0, len(withdrawals))
	for _, w := range withdrawals {
		res = append(res, &pbbeacon.Withdrawal{
			WithdrawalIndex: uint64(w.Index),
			ValidatorIndex:  uint64(w.ValidatorIndex),
			Address:         w.Address[:],
			Gwei:            uint64(w.Amount),
		})
	}
	return res
}

func signedBlsToExecutionChangeToProto(signedBlsToExecutionChanges []*capella.SignedBLSToExecutionChange) []*pbbeacon.SignedBLSToExecutionChange {
	res := make([]*pbbeacon.SignedBLSToExecutionChange, 0, len(signedBlsToExecutionChanges))
	for _, b := range signedBlsToExecutionChanges {
		res = append(res, &pbbeacon.SignedBLSToExecutionChange{
			Message:   blsToExecutionChangeToProto(b.Message),
			Signature: b.Signature[:],
		})
	}
	return res
}

func blsToExecutionChangeToProto(blsToExecutionChange *capella.BLSToExecutionChange) *pbbeacon.BLSToExecutionChange {
	return &pbbeacon.BLSToExecutionChange{
		ValidatorIndex:     uint64(blsToExecutionChange.ValidatorIndex),
		FromBlsPubKey:      blsToExecutionChange.FromBLSPubkey[:],
		ToExecutionAddress: blsToExecutionChange.ToExecutionAddress[:],
	}
}

func kzgCommitmentsToProto(kzgCommitments []deneb.KZGCommitment) [][]byte {
	res := make([][]byte, 0, len(kzgCommitments))
	for _, k := range kzgCommitments {
		res = append(res, k[:])
	}
	return res
}

func blobsToProto(blobSidecars []*deneb.BlobSidecar) []*pbbeacon.Blob {
	res := make([]*pbbeacon.Blob, 0, len(blobSidecars))
	for _, b := range blobSidecars {
		res = append(res, &pbbeacon.Blob{
			Index:                       uint64(b.Index),
			Blob:                        b.Blob[:],
			KzgCommitment:               b.KZGCommitment[:],
			KzgProof:                    b.KZGProof[:],
			KzgCommitmentInclusionProof: kgzCommitmentInclusionProofToProto(b.KZGCommitmentInclusionProof),
		})
	}
	return res
}

func kgzCommitmentInclusionProofToProto(kzgCommitmentInclusionProof deneb.KZGCommitmentInclusionProof) [][]byte {
	res := make([][]byte, 0, len(kzgCommitmentInclusionProof))
	for _, k := range kzgCommitmentInclusionProof {
		res = append(res, k[:])
	}
	return res
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
