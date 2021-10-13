package relay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"time"

	poly_bridge_sdk "github.com/polynetwork/poly-bridge/bridgesdk"

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
	bridgeSdk   *poly_bridge_sdk.BridgeSdk
	clients     []*ethclient.Client
	ethConfig   *config.EthConfig
	polyConfig  *config.PolyConfig
	conf        *config.Config
	account     accounts.Account
	keyStore    *tools.EthKeyStore
	nonce       *uint64
	idx         int
}

func NewPolyToEth(polyToEthCh chan string, polySdk *sdk.PolySdk, bridgeSdk *poly_bridge_sdk.BridgeSdk, clients []*ethclient.Client, ethConfig *config.EthConfig, polyConfig *config.PolyConfig, conf *config.Config, account accounts.Account, keyStore *tools.EthKeyStore) *PolyToEth {
	return &PolyToEth{polyToEthCh: polyToEthCh, doneCh: make(chan struct{}), polySdk: polySdk, bridgeSdk: bridgeSdk, clients: clients, ethConfig: ethConfig, polyConfig: polyConfig, conf: conf, account: account, keyStore: keyStore}
}

func randIdx(size int) int {
	return int(rand.Uint32()) % size
}

func (ctx *PolyToEth) checkGasLimit(hash string, limit uint64) error {
	if ctx.ethConfig.SideChainId == ctx.conf.ArbConfig.SideChainId {
		if limit > 4000000 {
			return fmt.Errorf("Skipping poly tx %s for gas limit too high %d ", hash, limit)
		}
		return nil
	}
	if limit > 300000 {
		return fmt.Errorf("Skipping poly tx %s for gas limit too high %d ", hash, limit)
	}
	return nil
}

func (ctx *PolyToEth) getNonce() uint64 {
	if ctx.nonce == nil {
		nonce, err := ctx.clients[randIdx(len(ctx.clients))].NonceAt(context.Background(), ctx.account.Address, nil)
		if err != nil {
			log.Fatalf("NonceAt failed:%v", err)
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
		log.Fatalf("polySdk.GetSmartContractEvent failed:%v", err)
	}

	polyTxHeight, err := polySdk.GetBlockHeightByTxHash(polyTxHash)
	if err != nil {
		log.Fatalf("polySdk.GetBlockHeightByTxHash failed:%v", err)
	}

	polyEpochHeight := ctx.findLatestPolyEpochHeight()

	hdr, err := polySdk.GetHeaderByHeight(polyTxHeight + 1)
	if err != nil {
		log.Fatalf("polySdk.GetHeaderByHeight failed:%v", err)
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

	if !ctx.conf.IsWhitelistMethod(merkleValue.MakeTxParam.Method) && !ctx.conf.Force {
		log.Errorf("method %s forbiden for poly_hash %s", merkleValue.MakeTxParam.Method, polyTxHash)
		return nil
	}
	if merkleValue.MakeTxParam.ToChainID != ctx.ethConfig.SideChainId {
		log.Errorf("ignored because ToChainID not match for poly_hash %s, got %d expect %d", polyTxHash, merkleValue.MakeTxParam.ToChainID, ctx.ethConfig.SideChainId)
		return nil
	}

	if ctx.conf.Print {
		sink := common1.NewZeroCopySink(nil)
		merkleValue.MakeTxParam.Serialization(sink)
		log.Infof(
			"FromChainID:%d ToChainID:%d method:%s args:%s MakeTxParam:%s",
			merkleValue.FromChainID,
			merkleValue.MakeTxParam.ToChainID,
			merkleValue.MakeTxParam.Method,
			hex.EncodeToString(merkleValue.MakeTxParam.Args),
			hex.EncodeToString(sink.Bytes()),
		)
		os.Exit(1)
	}
	if !ctx.isPaid(merkleValue) {
		log.Infof("%v skipped because not paid", polyEvt.TxHash)
		return nil
	}

	return ctx.makeTx(hdr, merkleValue, hp, anchor, auditpath)

}

func (ctx *PolyToEth) isPaid(param *common2.ToMerkleValue) bool {
	if ctx.conf.CheckMerkleRoot {
		return true
	}
	if ctx.conf.Force {
		return true
	}

	txHash := hex.EncodeToString(param.MakeTxParam.TxHash)
	req := &poly_bridge_sdk.CheckFeeReq{Hash: txHash, ChainId: param.FromChainID}
	c := 0
	for {
		start := time.Now()
		resp, err := ctx.bridgeSdk.CheckFee([]*poly_bridge_sdk.CheckFeeReq{req})
		if err != nil {
			log.Errorf("CheckFee failed:%v, TxHash:%s FromChainID:%d", err, txHash, param.FromChainID)
			time.Sleep(time.Second)
			continue
		}
		log.Infof("CheckFee took %s", time.Now().Sub(start).String())
		if len(resp) != 1 {
			log.Errorf("CheckFee resp invalid, length %d, TxHash:%s FromChainID:%d", len(resp), txHash, param.FromChainID)
			time.Sleep(time.Second)
			continue
		}

		switch resp[0].PayState {
		case poly_bridge_sdk.STATE_HASPAY:
			return true
		case poly_bridge_sdk.STATE_NOTPAY:
			return false
		case poly_bridge_sdk.STATE_NOTPOLYPROXY:
			log.Info("CheckFee STATE_NOTPOLYPROXY, TxHash:%s ", txHash)
			return false
		case poly_bridge_sdk.STATE_NOTCHECK:
			log.Errorf("CheckFee STATE_NOTCHECK, TxHash:%s FromChainID:%d Poly Hash:%s, wait...", txHash, param.FromChainID, hex.EncodeToString(common1.ToArrayReverse(param.TxHash)))
			if c >= 1 {
				return false
			}
			c++
			time.Sleep(time.Second)
			continue
		}

	}
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
		log.Fatalf("PolyToEth instance.GetCurEpochStartHeight failed:%v", err)
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

func (ctx *PolyToEth) checkMerkleRoot(rawAuditPath []byte, header *polytypes.Header) {
	root, err := tools.MerkleRoot(rawAuditPath, header.CrossStateRoot.ToArray())
	if err != nil {
		log.Warn("wrong root", err)
	}

	log.Info("expect root:", hex.EncodeToString(common1.ToArrayReverse(root)))
	log.Info("actual root:", header.CrossStateRoot.ToHexString())
	return
}

func (ctx *PolyToEth) makeTx(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, rawAuditPath []byte) []byte {
	var (
		sigs       []byte
		headerData []byte
	)
	if ctx.conf.CheckMerkleRoot {
		ctx.checkMerkleRoot(rawAuditPath, header)
		return nil
	}

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

func (ctx *PolyToEth) forceLimit() uint64 {
	if ctx.ethConfig.SideChainId == ctx.conf.ArbConfig.SideChainId {
		return 4000000
	}
	return 500000
}

func (ctx *PolyToEth) SendTx(polyTxHash string) {
	log.Infof("SendTx %s ToChainID %d", polyTxHash, ctx.ethConfig.SideChainId)

	idx := randIdx(len(ctx.clients))
	ctx.idx = idx
	client := ctx.clients[idx]

	nonce := ctx.getNonce()
	txData := ctx.getTxData(polyTxHash)
	if len(txData) == 0 {
		return
	}

	timerCtx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	var err error

	gasPrice := ctx.conf.GasPrice
	if gasPrice == nil {
		gasPrice, err = client.SuggestGasPrice(timerCtx)
		if err != nil {
			log.Fatalf("client.SuggestGasPrice failed:%v chain:%d", err, ctx.ethConfig.SideChainId)
		}
		if !ctx.conf.IsEth(ctx.ethConfig.SideChainId) {
			gasPrice = big.NewInt(0).Quo(big.NewInt(0).Mul(gasPrice, big.NewInt(12)), big.NewInt(10))
		}
	}

	contractaddr := common.HexToAddress(ctx.ethConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: ctx.account.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}

	var gasLimit uint64
	if ctx.conf.Force {
		gasLimit = ctx.forceLimit()
	} else {
		gasLimit, err = client.EstimateGas(timerCtx, callMsg)
		if err != nil {
			log.Errorf("client.EstimateGas failed:%v polyTxHash:%s", err, polyTxHash)
			return
		}
		// Check gas limit
		gasLimit = uint64(float32(gasLimit) * 1.1)
		if e := ctx.checkGasLimit(polyTxHash, gasLimit); e != nil {
			log.Errorf("Skipped poly tx %s for gas limit too high %v", polyTxHash, gasLimit)
			return
		}
	}

	tx := types.NewTransaction(nonce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := ctx.keyStore.SignTransaction(tx, ctx.account)
	if err != nil {
		log.Fatalf("keyStore.SignTransaction failed:%v", err)
	}

	hash, err := ctx.sendTxAndReturnHash(timerCtx, signedtx)
	if err != nil {
		log.Errorf("sendTxAndReturnHash failed:%v account:%s gasPrice:%d gasLimit:%d idx:%d", err, ctx.account.Address.Hex(), gasPrice.Int64(), gasLimit, idx)
		time.Sleep(time.Second * 1)
		return
	}

	isSuccess := waitTransactionConfirm(client, polyTxHash, hash)
	if isSuccess {
		log.Infof("successful to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d, chain:%d, poly_hash: %s, gasPrice: %d, idx: %d)",
			hash.String(), ctx.account.Address.Hex(), nonce, ctx.ethConfig.SideChainId, polyTxHash, gasPrice.Int64(), idx)
	} else {
		log.Errorf("failed to relay tx to ethereum: (eth_hash: %s, account: %s, nonce: %d, chain:%d, poly_hash: %s, gasPrice: %d, idx: %d)",
			hash.String(), ctx.account.Address.Hex(), nonce, ctx.ethConfig.SideChainId, polyTxHash, gasPrice.Int64(), idx)
	}
}

func (ctx *PolyToEth) sendTxAndReturnHash(timerCtx context.Context, signedtx *types.Transaction) (hash common.Hash, err error) {

	conf := ctx.conf
	switch ctx.ethConfig.SideChainId {
	case conf.OKConfig.SideChainId:
		hash, err = ctx.clients[ctx.idx].SendOKTransaction(timerCtx, signedtx)
	default:
		err = ctx.clients[ctx.idx].SendTransaction(timerCtx, signedtx)
		if err != nil {
			log.Errorf("SendTransaction failed:%v, SideChainId:%d idx:%d", err, ctx.ethConfig.SideChainId, ctx.idx)
			return
		}
		hash = signedtx.Hash()
	}

	return
}

func waitTransactionConfirm(client *ethclient.Client, polyTxHash string, hash common.Hash) bool {
	start := time.Now()
	for {
		if time.Now().After(start.Add(time.Minute * 1)) {
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
