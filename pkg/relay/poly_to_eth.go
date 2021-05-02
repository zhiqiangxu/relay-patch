package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	vconfig "github.com/ontio/ontology/consensus/vbft/config"
	sdk "github.com/polynetwork/poly-go-sdk"
	sdkcom "github.com/polynetwork/poly-go-sdk/common"
	common1 "github.com/polynetwork/poly/common"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/zhiqiangxu/relay-patch/config"
	"github.com/zhiqiangxu/relay-patch/pkg/eccd_abi"
	"github.com/zhiqiangxu/relay-patch/pkg/eccm_abi"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/relay-patch/pkg/tools"
)

// PolyToEth ...
type PolyToEth struct {
	polyToEthCh chan string
	doneCh      chan struct{}
	polySdk     *sdk.PolySdk
	clients     []*ethclient.Client
	ethConfig   *config.EthConfig
	polyConfig  *config.PolyConfig
	account     accounts.Account
	keyStore    *tools.EthKeyStore
	nonce       *uint64
	idx         int
}

func NewPolyToEth(polyToEthCh chan string, polySdk *sdk.PolySdk, clients []*ethclient.Client, ethConfig *config.EthConfig, polyConfig *config.PolyConfig, account accounts.Account, keyStore *tools.EthKeyStore) *PolyToEth {
	return &PolyToEth{polyToEthCh: polyToEthCh, doneCh: make(chan struct{}), polySdk: polySdk, clients: clients, ethConfig: ethConfig, polyConfig: polyConfig, account: account, keyStore: keyStore}
}

func randIdx(size int) int {
	return int(rand.Uint32()) % size
}

func (ctx *PolyToEth) getNonce() uint64 {
	if ctx.nonce == nil {
		nonce, err := ctx.clients[randIdx(len(ctx.clients))].PendingNonceAt(context.Background(), ctx.account.Address)
		if err != nil {
			log.Fatalf("PendingNonceAt failed:%v", err)
		}
		ctx.nonce = &nonce
	}

	nonce := *ctx.nonce
	*ctx.nonce += 1

	return nonce
}

func (ctx *PolyToEth) Start() {
	for {
		select {
		case txHash, ok := <-ctx.polyToEthCh:
			if !ok {
				return
			}

			ctx.SendTx(txHash)
		case <-ctx.doneCh:
			return
		}

	}
}

func (ctx *PolyToEth) Stop() {
	close(ctx.doneCh)
}

func GetKeyParams(polySdk *sdk.PolySdk, polyConfig *config.PolyConfig, polyTxHash string, polyTxHeight uint32) (*common2.ToMerkleValue, []byte, *sdkcom.SmartContactEvent) {
	polyEvt, err := polySdk.GetSmartContractEvent(polyTxHash)
	if err != nil {
		log.Fatalf("polySdk.GetSmartContractEvent failed:%v poly_hash:%s", err, polyTxHash)
	}

	if polyTxHeight == 0 {
		polyTxHeight, err = polySdk.GetBlockHeightByTxHash(polyTxHash)
		if err != nil {
			log.Fatalf("polySdk.GetBlockHeightByTxHash failed:%v poly_hash:%s", err, polyTxHash)
		}
	}

	for _, notify := range polyEvt.Notify {
		if notify.ContractAddress == polyConfig.EntranceContractAddress {
			states := notify.States.([]interface{})
			method, _ := states[0].(string)
			if method != "makeProof" {
				continue
			}

			proof, err := polySdk.GetCrossStatesProof(polyTxHeight, states[5].(string))
			if err != nil {
				log.Errorf("polySdk.GetCrossStatesProof - failed to get proof for key %s: %v", states[5].(string), err)
				continue
			}
			auditpath, _ := hex.DecodeString(proof.AuditPath)
			value, _, _, _ := tools.ParseAuditpath(auditpath)
			param := &common2.ToMerkleValue{}
			if err := param.Deserialization(common1.NewZeroCopySource(value)); err != nil {
				log.Errorf("failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
				continue
			}

			return param, auditpath, polyEvt
		}
	}
	return nil, nil, nil
}

func (ctx *PolyToEth) getTxData(polyTxHash string) []byte {
	polySdk := ctx.polySdk
	polyEvt, err := polySdk.GetSmartContractEvent(polyTxHash)
	if err != nil {
		log.Fatal(fmt.Sprintf("polySdk.GetSmartContractEvent failed:%v", err))
	}

	polyTxHeight, err := polySdk.GetBlockHeightByTxHash(polyTxHash)
	if err != nil {
		log.Fatal(fmt.Sprintf("polySdk.GetBlockHeightByTxHash failed:%v", err))
	}

	polyEpochHeight := ctx.findLatestPolyEpochHeight()

	hdr, err := polySdk.GetHeaderByHeight(polyTxHeight + 1)
	if err != nil {
		log.Fatal(fmt.Sprintf("polySdk.GetHeaderByHeight failed:%v", err))
	}

	isCurr := polyEpochHeight <= polyTxHeight
	isEpoch, _, err := ctx.isHeaderEpoch(hdr)
	if err != nil {
		log.Fatalf("isHeaderEpoch failed: %v", err)
	}

	var (
		anchor *polytypes.Header
		hp     string
	)

	if !isCurr {
		anchor, _ = polySdk.GetHeaderByHeight(polyEpochHeight + 1)
		proof, _ := polySdk.GetMerkleProof(polyTxHeight+1, polyEpochHeight+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = polySdk.GetHeaderByHeight(polyTxHeight + 2)
		proof, _ := polySdk.GetMerkleProof(polyTxHeight+1, polyTxHeight+2)
		hp = proof.AuditPath
	}

	merkleValue, auditpath, polyEvt := GetKeyParams(ctx.polySdk, ctx.polyConfig, polyTxHash, polyTxHeight)
	if merkleValue == nil {
		log.Errorf("MerkleValue empty for poly_hash %s", polyTxHash)
		return nil
	}

	if merkleValue.MakeTxParam.ToChainID != ctx.ethConfig.SideChainId {
		log.Errorf("ignored because ToChainID not match for poly_hash %s, got %d expect %d", polyTxHash, merkleValue.MakeTxParam.ToChainID, ctx.ethConfig.SideChainId)
		return nil
	}

	if !isPaid(merkleValue) {
		log.Infof("%v skipped because not paid", polyEvt.TxHash)
		return nil
	}

	return ctx.makeTx(hdr, merkleValue, hp, anchor, auditpath)

}

func (ctx *PolyToEth) findLatestPolyEpochHeight() uint32 {
	address := common.HexToAddress(ctx.ethConfig.ECCDContractAddress)
	instance, err := eccd_abi.NewEthCrossChainData(address, ctx.clients[ctx.idx])
	if err != nil {
		log.Fatalf("eccd_abi.NewEthCrossChainData failed:%v", err)
		return 0
	}

	height, err := instance.GetCurEpochStartHeight(nil)
	if err != nil {
		log.Fatalf("instance.GetCurEpochStartHeight failed:%v", err)
	}

	return uint32(height)
}

func (ctx *PolyToEth) isHeaderEpoch(hdr *polytypes.Header) (bool, []byte, error) {
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, blkInfo); err != nil {
		return false, nil, fmt.Errorf("vconfig.VbftBlockInfo json.Unmarshal error: %s", err)
	}
	if hdr.NextBookkeeper == common1.ADDRESS_EMPTY || blkInfo.NewChainConfig == nil {
		return false, nil, nil
	}

	client := ctx.clients[ctx.idx]
	eccdAddr := common.HexToAddress(ctx.ethConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, client)
	if err != nil {
		return false, nil, fmt.Errorf("eccd_abi.NewEthCrossChainData failed:%v", err)
	}
	rawKeepers, err := eccd.GetCurEpochConPubKeyBytes(nil)
	if err != nil {
		return false, nil, fmt.Errorf("eccd.GetCurEpochConPubKeyBytes failed:%v", err)
	}

	var bookkeepers []keypair.PublicKey
	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	sink := common1.NewZeroCopySink(nil)
	sink.WriteUint64(uint64(len(bookkeepers)))
	for _, key := range bookkeepers {
		raw := tools.GetNoCompresskey(key)
		publickeys = append(publickeys, raw...)
		sink.WriteVarBytes(crypto.Keccak256(tools.GetEthNoCompressKey(key)[1:])[12:])
	}
	if bytes.Equal(rawKeepers, sink.Bytes()) {
		return false, nil, nil
	}
	return true, publickeys, nil
}

func (ctx *PolyToEth) makeTx(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, rawAuditPath []byte) []byte {
	var (
		sigs       []byte
		headerData []byte
	)
	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}

	client := ctx.clients[ctx.idx]
	eccdAddr := common.HexToAddress(ctx.ethConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, client)
	if err != nil {
		log.Fatalf("eccd_abi.NewEthCrossChainData failed:%v", err)
	}
	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])

	res, err := eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx)
	if err != nil {
		log.Fatalf("eccd.CheckIfFromChainTxExist failed:%v", err)
	}

	if res {
		log.Infof("already relayed to sidechain: ( from_chain_id: %d, to_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.MakeTxParam.ToChainID, param.TxHash, param.MakeTxParam.TxHash)
		return nil
	}

	rawProof, _ := hex.DecodeString(headerProof)
	var rawAnchor []byte
	if anchorHeader != nil {
		rawAnchor = anchorHeader.GetMessage()
	}

	headerData = header.GetMessage()
	contractAbi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		log.Fatalf("abi.JSON failed for eccm:%v", err)
	}

	txData, err := contractAbi.Pack("verifyHeaderAndExecuteTx", rawAuditPath, headerData, rawProof, rawAnchor, sigs)
	if err != nil {
		log.Fatalf("contractAbi.Pack failed:%v", err)
	}

	return txData
}

func (ctx *PolyToEth) SendTx(polyTxHash string) {
	log.Infof("SendTx %s ToChainID %d", polyTxHash, ctx.ethConfig.SideChainId)

	idx := randIdx(len(ctx.clients))
	ctx.idx = idx
	client := ctx.clients[idx]

	txData := ctx.getTxData(polyTxHash)
	if len(txData) == 0 {
		return
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("client.SuggestGasPrice failed:%v", err)
	}

	contractaddr := common.HexToAddress(ctx.ethConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: ctx.account.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}
	gasLimit, err := client.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("client.EstimateGas failed:%v", err)
		return
	}

	nonce := ctx.getNonce()
	tx := types.NewTransaction(nonce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := ctx.keyStore.SignTransaction(tx, ctx.account)
	if err != nil {
		log.Fatalf("keyStore.SignTransaction failed:%v", err)
	}

	err = client.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("client.SendTransaction failed:%v", err)
		time.Sleep(time.Second * 1)
		return
	}

	hash := signedtx.Hash()
	isSuccess := waitTransactionConfirm(client, polyTxHash, hash)
	if isSuccess {
		log.Infof("successful to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d, chain:%d, poly_hash: %s)",
			hash.String(), ctx.account.Address.Hex(), nonce, ctx.ethConfig.SideChainId, polyTxHash)
	} else {
		log.Errorf("failed to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d, chain:%d, poly_hash: %s)",
			hash.String(), ctx.account.Address.Hex(), nonce, ctx.ethConfig.SideChainId, polyTxHash)
	}
}

func waitTransactionConfirm(client *ethclient.Client, polyTxHash string, hash common.Hash) bool {
	start := time.Now()
	for {
		if time.Now().After(start.Add(time.Minute * 3)) {
			return false
		}
		time.Sleep(time.Second * 1)
		_, ispending, err := client.TransactionByHash(context.Background(), hash)
		if err != nil {
			continue
		}
		log.Debugf("( eth_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash, ispending)
		if ispending == true {
			continue
		} else {
			receipt, err := client.TransactionReceipt(context.Background(), hash)
			if err != nil {
				continue
			}
			return receipt.Status == types.ReceiptStatusSuccessful
		}
	}
}
