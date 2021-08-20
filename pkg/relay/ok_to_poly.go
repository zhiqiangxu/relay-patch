package relay

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/gogo/protobuf/proto"
	oksdk "github.com/okex/exchain-go-sdk"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/types"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/relay-patch/pkg/tools"
)

type CosmosHeader struct {
	Header  types.Header
	Commit  *types.Commit
	Valsets []*types.Validator
}

type CosmosProofValue struct {
	Kp    string
	Value []byte
}

func (chain *EthToPoly) commitOKProof(height uint32, proof []byte, value []byte, txhash []byte) (polyHash string, err error) {

	okProof := new(tools.ETHProof)
	err = json.Unmarshal(proof, okProof)
	if err != nil {
		log.Errorf("commitOKProof json.Unmarshal failed:%v", err)
		return
	}
	var mproof merkle.Proof
	err = proto.UnmarshalText(okProof.StorageProofs[0].Proof[0], &mproof)
	if err != nil {
		log.Errorf("commitOKProof proto.UnmarshalText failed:%v", err)
		return
	}

	keyPath := "/"
	for i := range mproof.Ops {
		op := mproof.Ops[len(mproof.Ops)-1-i]
		keyPath += "x:" + hex.EncodeToString(op.Key)
		keyPath += "/"
	}
	keyPath = strings.TrimSuffix(keyPath, "/")

	tmClient := chain.tmClients[randIdx(len(chain.tmClients))]
	targetHeight := int64(height + 1)
	cr, err := tmClient.Tendermint().QueryCommitResult(targetHeight)
	if err != nil {
		log.Errorf("commitOKProof QueryCommitResult failed:%v targetHeight:%d", err, targetHeight)
		return
	}
	vSet, err := getValidators(tmClient, targetHeight)
	if err != nil {
		log.Errorf("commitOKProof getValidators failed:%v", err)
		return
	}
	hdr := CosmosHeader{
		Header:  *cr.Header,
		Commit:  cr.Commit,
		Valsets: vSet,
	}

	raw, err := chain.cdc.MarshalBinaryBare(hdr)
	if err != nil {
		return
	}

	storageProof, err := chain.cdc.MarshalBinaryBare(mproof)
	if err != nil {
		return
	}

	txData, err := chain.cdc.MarshalBinaryBare(&CosmosProofValue{Kp: keyPath, Value: value})
	if err != nil {
		return
	}

	return chain.commitProof(uint32(targetHeight), storageProof, txData, raw, txhash)
}

func getValidators(tmClient *oksdk.Client, h int64) ([]*types.Validator, error) {
	vr, err := tmClient.Tendermint().QueryValidatorsResult(h)
	if err != nil {
		log.Errorf("getValidators on height :%d failed:%v", h, err)
		return nil, err
	}

	return vr.Validators, nil
}
