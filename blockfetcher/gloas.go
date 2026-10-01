package blockfetcher

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	pbbeacon "github.com/pinax-network/firehose-beacon/pb/sf/beacon/type/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// gloasBlockID returns the Firehose block ID of a Gloas block. Whether a block's execution payload became canonical is
// only decided by the next block, which is itself not final when we emit the block. To let firehose-core detect a later
// change of the payload status like any other fork (parent ID mismatch), the ID encodes the payload status: it is the
// beacon block root if the payload was included, and a hash derived from the root otherwise. This mirrors the ePBS
// fork choice, which tracks (root, payload status) pairs.
func gloasBlockID(root phase0.Root, payloadCanonical bool) string {
	if payloadCanonical {
		return root.String()
	}

	h := sha256.New()
	h.Write([]byte("firehose-beacon/empty-payload/"))
	h.Write(root[:])
	return fmt.Sprintf("%#x", h.Sum(nil))
}

// toGloasBody converts a Gloas beacon block. The envelope is nil when the canonical chain did not build on this
// block's payload, in which case no blobs are embedded either.
func toGloasBody(signedBlock *gloas.SignedBeaconBlock, envelope *gloas.SignedExecutionPayloadEnvelope, blobs []*deneb.Blob) *pbbeacon.GloasBody {
	blockBody := signedBlock.Message.Body
	res := &pbbeacon.GloasBody{
		RandoReveal:               blockBody.RANDAOReveal[:],
		Eth1Data:                  eth1DataToProto(blockBody.ETH1Data),
		Graffiti:                  blockBody.Graffiti[:],
		ProposerSlashings:         proposerSlashingsToProto(blockBody.ProposerSlashings),
		AttesterSlashings:         gloasAttesterSlashingsToProto(blockBody.AttesterSlashings),
		Attestations:              gloasAttestationsToProto(blockBody.Attestations),
		Deposits:                  depositsToProto(blockBody.Deposits),
		VoluntaryExits:            voluntaryExitsToProto(blockBody.VoluntaryExits),
		SyncAggregate:             syncAggregateToProto(blockBody.SyncAggregate),
		BlsToExecutionChanges:     signedBlsToExecutionChangeToProto(blockBody.BLSToExecutionChanges),
		SignedExecutionPayloadBid: signedExecutionPayloadBidToProto(blockBody.SignedExecutionPayloadBid),
		PayloadAttestations:       payloadAttestationsToProto(blockBody.PayloadAttestations),
		ParentExecutionRequests:   gloasExecutionRequestsToProto(blockBody.ParentExecutionRequests),
	}

	if envelope != nil {
		res.ExecutionPayloadEnvelope = signedExecutionPayloadEnvelopeToProto(envelope)
		res.EmbeddedBlobs = gloasBlobsToProto(blobs, blockBody.SignedExecutionPayloadBid.Message.BlobKZGCommitments)
	}

	return res
}

func gloasAttesterSlashingsToProto(attesterSlashings []*gloas.AttesterSlashing) []*pbbeacon.AttesterSlashing {
	res := make([]*pbbeacon.AttesterSlashing, 0, len(attesterSlashings))
	for _, a := range attesterSlashings {
		res = append(res, &pbbeacon.AttesterSlashing{
			Attestation_1: gloasIndexedAttestationToProto(a.Attestation1),
			Attestation_2: gloasIndexedAttestationToProto(a.Attestation2),
		})
	}
	return res
}

func gloasIndexedAttestationToProto(indexedAttestation *gloas.IndexedAttestation) *pbbeacon.IndexedAttestation {
	return &pbbeacon.IndexedAttestation{
		AttestingIndices: indexedAttestation.AttestingIndices,
		Data:             attestationDataToProto(indexedAttestation.Data),
		Signature:        indexedAttestation.Signature[:],
	}
}

func gloasAttestationsToProto(attestations []*gloas.Attestation) []*pbbeacon.ElectraAttestation {
	res := make([]*pbbeacon.ElectraAttestation, 0, len(attestations))
	for _, a := range attestations {
		res = append(res, &pbbeacon.ElectraAttestation{
			AggregationBits: a.AggregationBits,
			Data:            attestationDataToProto(a.Data),
			Signature:       a.Signature[:],
			CommitteeBits:   a.CommitteeBits[:],
		})
	}
	return res
}

func signedExecutionPayloadBidToProto(signedBid *gloas.SignedExecutionPayloadBid) *pbbeacon.SignedExecutionPayloadBid {
	bid := signedBid.Message
	return &pbbeacon.SignedExecutionPayloadBid{
		Message: &pbbeacon.ExecutionPayloadBid{
			ParentBlockHash:       bid.ParentBlockHash[:],
			ParentBlockRoot:       bid.ParentBlockRoot[:],
			BlockHash:             bid.BlockHash[:],
			PrevRandao:            bid.PrevRandao[:],
			FeeRecipient:          bid.FeeRecipient[:],
			GasLimit:              bid.GasLimit,
			BuilderIndex:          uint64(bid.BuilderIndex),
			Slot:                  uint64(bid.Slot),
			Value:                 uint64(bid.Value),
			ExecutionPayment:      uint64(bid.ExecutionPayment),
			BlobKzgCommitments:    kzgCommitmentsToProto(bid.BlobKZGCommitments),
			ExecutionRequestsRoot: bid.ExecutionRequestsRoot[:],
		},
		Signature: signedBid.Signature[:],
	}
}

func payloadAttestationsToProto(payloadAttestations []*gloas.PayloadAttestation) []*pbbeacon.PayloadAttestation {
	res := make([]*pbbeacon.PayloadAttestation, 0, len(payloadAttestations))
	for _, p := range payloadAttestations {
		res = append(res, &pbbeacon.PayloadAttestation{
			AggregationBits: p.AggregationBits[:],
			Data: &pbbeacon.PayloadAttestationData{
				BeaconBlockRoot:   p.Data.BeaconBlockRoot[:],
				Slot:              uint64(p.Data.Slot),
				PayloadPresent:    p.Data.PayloadPresent,
				BlobDataAvailable: p.Data.BlobDataAvailable,
			},
			Signature: p.Signature[:],
		})
	}
	return res
}

func gloasExecutionRequestsToProto(executionRequests *gloas.ExecutionRequests) *pbbeacon.ExecutionRequest {
	if executionRequests == nil {
		return nil
	}
	return &pbbeacon.ExecutionRequest{
		Deposits:        depositRequestsToProto(executionRequests.Deposits),
		Withdrawals:     withdrawalRequestsToProto(executionRequests.Withdrawals),
		Consolidations:  consolidationRequestsToProto(executionRequests.Consolidations),
		BuilderDeposits: builderDepositRequestsToProto(executionRequests.BuilderDeposits),
		BuilderExits:    builderExitRequestsToProto(executionRequests.BuilderExits),
	}
}

func builderDepositRequestsToProto(deposits []*gloas.BuilderDepositRequest) []*pbbeacon.BuilderDepositRequest {
	res := make([]*pbbeacon.BuilderDepositRequest, 0, len(deposits))
	for _, d := range deposits {
		res = append(res, &pbbeacon.BuilderDepositRequest{
			PubKey:                d.Pubkey[:],
			WithdrawalCredentials: d.WithdrawalCredentials,
			Amount:                uint64(d.Amount),
			Signature:             d.Signature[:],
		})
	}
	return res
}

func builderExitRequestsToProto(exits []*gloas.BuilderExitRequest) []*pbbeacon.BuilderExitRequest {
	res := make([]*pbbeacon.BuilderExitRequest, 0, len(exits))
	for _, e := range exits {
		res = append(res, &pbbeacon.BuilderExitRequest{
			SourceAddress: e.SourceAddress[:],
			PubKey:        e.Pubkey[:],
		})
	}
	return res
}

func signedExecutionPayloadEnvelopeToProto(signedEnvelope *gloas.SignedExecutionPayloadEnvelope) *pbbeacon.SignedExecutionPayloadEnvelope {
	envelope := signedEnvelope.Message
	return &pbbeacon.SignedExecutionPayloadEnvelope{
		Message: &pbbeacon.ExecutionPayloadEnvelope{
			Payload:               gloasExecutionPayloadToProto(envelope.Payload),
			ExecutionRequests:     gloasExecutionRequestsToProto(envelope.ExecutionRequests),
			BuilderIndex:          uint64(envelope.BuilderIndex),
			BeaconBlockRoot:       envelope.BeaconBlockRoot[:],
			ParentBeaconBlockRoot: envelope.ParentBeaconBlockRoot[:],
		},
		Signature: signedEnvelope.Signature[:],
	}
}

func gloasExecutionPayloadToProto(executionPayload *gloas.ExecutionPayload) *pbbeacon.GloasExecutionPayload {
	return &pbbeacon.GloasExecutionPayload{
		ParentHash:      executionPayload.ParentHash[:],
		FeeRecipient:    executionPayload.FeeRecipient[:],
		StateRoot:       executionPayload.StateRoot[:],
		ReceiptsRoot:    executionPayload.ReceiptsRoot[:],
		LogsBloom:       executionPayload.LogsBloom[:],
		PrevRandao:      executionPayload.PrevRandao[:],
		BlockNumber:     executionPayload.BlockNumber,
		GasLimit:        executionPayload.GasLimit,
		GasUsed:         executionPayload.GasUsed,
		Timestamp:       timestamppb.New(time.Unix(int64(executionPayload.Timestamp), 0)),
		ExtraData:       executionPayload.ExtraData[:],
		BaseFeePerGas:   executionPayload.BaseFeePerGas.Bytes(),
		BlockHash:       executionPayload.BlockHash[:],
		Transactions:    transactionsToProto(executionPayload.Transactions),
		Withdrawals:     withdrawalsToProto(executionPayload.Withdrawals),
		BlobGasUsed:     executionPayload.BlobGasUsed,
		ExcessBlobGas:   executionPayload.ExcessBlobGas,
		BlockAccessList: executionPayload.BlockAccessList,
		SlotNumber:      executionPayload.SlotNumber,
	}
}

// gloasBlobsToProto pairs the blobs returned by the beacon node's blobs endpoint, which come back in commitment
// order, with the commitments from the block's bid.
func gloasBlobsToProto(blobs []*deneb.Blob, commitments []deneb.KZGCommitment) []*pbbeacon.Blob {
	res := make([]*pbbeacon.Blob, 0, len(blobs))
	for i, b := range blobs {
		blob := &pbbeacon.Blob{
			Index: uint64(i),
			Blob:  b[:],
		}
		if i < len(commitments) {
			blob.KzgCommitment = commitments[i][:]
		}
		res = append(res, blob)
	}
	return res
}
