package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	cmcodec "github.com/cosmos/cosmos-sdk/codec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	oksdk "github.com/okex/exchain-go-sdk"
	"github.com/okex/exchain/app"
	"github.com/okex/exchain/app/codec"
	"github.com/ontio/ontology-crypto/keypair"
	vconfig "github.com/ontio/ontology/consensus/vbft/config"
	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/cross_chain_manager"
	sdk "github.com/polynetwork/poly-go-sdk"
	common1 "github.com/polynetwork/poly/common"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/eth"
	scom "github.com/polynetwork/poly/native/service/header_sync/common"
	"github.com/polynetwork/poly/native/service/utils"
	"github.com/zhiqiangxu/relay-patch/config"
	"github.com/zhiqiangxu/relay-patch/pkg/eccd_abi"
	"github.com/zhiqiangxu/relay-patch/pkg/eccm_abi"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/relay-patch/pkg/tools"
)

// EthToPoly ...
type EthToPoly struct {
	ethToPolyCh    chan string
	doneCh         chan struct{}
	polySdk        *sdk.PolySdk
	signer         *sdk.Account
	clients        []*ethclient.Client
	ethConfig      *config.EthConfig
	conf           *config.Config
	idx            int
	skippedSenders map[common.Address]bool
	tmClients      []*oksdk.Client
	cdc            *cmcodec.Codec
}

func NewEthToPoly(ethToPolyCh chan string, polySdk *sdk.PolySdk,
	signer *sdk.Account,
	clients []*ethclient.Client,
	tmClients []*oksdk.Client,
	ethConfig *config.EthConfig,
	conf *config.Config) *EthToPoly {
	skippedSenders := map[common.Address]bool{}
	for _, s := range conf.SkippedSenders {
		skippedSenders[common.HexToAddress(s)] = true
	}

	var cdc *cmcodec.Codec
	if conf.IsOK(ethConfig.SideChainId) {
		cdc = codec.MakeCodec(app.ModuleBasics)
	}
	return &EthToPoly{ethToPolyCh: ethToPolyCh, doneCh: make(chan struct{}), polySdk: polySdk, signer: signer, clients: clients, tmClients: tmClients, ethConfig: ethConfig, conf: conf, cdc: cdc, skippedSenders: skippedSenders}
}

func (chain *EthToPoly) Start() {
	for {
		select {
		case txHash, ok := <-chain.ethToPolyCh:
			if !ok {
				return
			}

			toChainID, polyTxHash := chain.MonitorTx(txHash)

			if polyTxHash != "" {
				waitPolyTxConfirm(polyTxHash, chain.polySdk)
				log.Infof("relayed tx %s on chain %d to chain %d with poly hash %s", txHash, chain.ethConfig.SideChainId, toChainID, polyTxHash)
			}
		case <-chain.doneCh:
			return
		}

	}
}

func waitPolyTxConfirm(polyTxHash string, polySdk *sdk.PolySdk) {
	for {
		time.Sleep(time.Second)
		tx, err := polySdk.GetTransaction(polyTxHash)
		if err != nil {
			log.Infof("waiting poly_hash %s", polyTxHash)
			continue
		}
		if tx == nil {
			log.Errorf("poly_hash %s not exists", polyTxHash)
			continue
		}
		break

	}
}

func (chain *EthToPoly) Stop() {
	close(chain.doneCh)
}

func (chain *EthToPoly) MonitorTx(ethTxHash string) (uint64, string) {
	log.Infof("MonitorTx %s FromChainID %d", ethTxHash, chain.ethConfig.SideChainId)
	idx := randIdx(len(chain.clients))
	chain.idx = idx
	client := chain.clients[idx]

	receipt, err := client.TransactionReceipt(context.Background(), common.HexToHash(ethTxHash))
	if err != nil {
		log.Fatalf("TransactionReceipt failed:%v", err)
	}
	eccmAddr := common.HexToAddress(chain.ethConfig.ECCMContractAddress)

	eccm, err := eccm_abi.NewEthCrossChainManager(eccmAddr, client)
	if err != nil {
		log.Fatalf("eccm_abi.NewEthCrossChainManager failed:%v", err)
	}
	for _, elog := range receipt.Logs {

		if elog.Address == eccmAddr {

			evt, err := eccm.ParseCrossChainEvent(*elog)
			if err != nil {
				log.Fatalf("eccm.ParseCrossChainEvent failed:%v", err)
			}

			param := &common2.MakeTxParam{}
			err = param.Deserialization(common1.NewZeroCopySource([]byte(evt.Rawdata)))
			if err != nil {
				log.Fatalf("param.Deserialization failed:%v", err)
			}

			if !chain.conf.IsWhitelistMethod(param.Method) && !chain.conf.Force {
				log.Errorf("method %s is forbiden", param.Method)
				return param.ToChainID, ""
			}
			if chain.ethConfig.ShouldSkip(evt.Sender) {
				log.Infof("sender %s is skipped", evt.Sender.Hex())
				return param.ToChainID, ""
			}

			raw, _ := chain.polySdk.GetStorage(utils.CrossChainManagerContractAddress.ToHexString(),
				append(append([]byte(cross_chain_manager.DONE_TX), utils.GetUint64Bytes(chain.ethConfig.SideChainId)...), param.CrossChainID...))

			if len(raw) != 0 {
				log.Infof("ccid %s (tx_hash: %s to_chainid: %d) already on poly",
					hex.EncodeToString(param.CrossChainID), evt.Raw.TxHash.Hex(), param.ToChainID)
				return param.ToChainID, ""
			} else {
				txIDBig := big.NewInt(0)
				txIDBig.SetBytes(evt.TxId)
				txID := tools.EncodeBigInt(txIDBig)
				txHash := evt.Raw.TxHash.Bytes()

				keyBytes, err := eth.MappingKeyAt(txID, "01")
				if err != nil {
					log.Fatalf("eth.MappingKeyAt failed:%v", err)
				}

				height := chain.decideProofHeight()
				heightHex := hexutil.EncodeBig(big.NewInt(height))
				proofKey := hexutil.Encode(keyBytes)

				proof, err := tools.GetProof(chain.ethConfig.RestURL[idx], chain.ethConfig.ECCDContractAddress, proofKey, heightHex)
				if err != nil {
					log.Fatalf("tools.GetProof failed:%v proofHeight:%d chainID:%d url:%s", err, height, chain.ethConfig.SideChainId, chain.ethConfig.RestURL[idx])
				}

				var polyTxHash string
				if chain.conf.IsOK(chain.ethConfig.SideChainId) {
					polyTxHash, err = chain.commitOKProof(uint32(height), proof, evt.Rawdata, txHash)
				} else {
					polyTxHash, err = chain.commitProof(uint32(height), proof, evt.Rawdata, []byte{}, txHash)
				}

				if err != nil {
					log.Fatalf("commitProof failed:%v", err)
				}

				return evt.ToChainId, polyTxHash

			}
		}
	}

	log.Warnf("eccm event not found for tx %s", ethTxHash)
	return 0, ""
}

func (chain *EthToPoly) decideProofHeight() int64 {
	conf := chain.conf
	switch chain.ethConfig.SideChainId {
	case conf.OKConfig.SideChainId:
		for {
			height, err := chain.clients[chain.idx].BlockNumber(context.Background())
			if err != nil {
				log.Errorf("decideProofHeight fail:%v", err)
				time.Sleep(time.Second)
				continue
			}
			return int64(height - 10)
		}
	default:
		return int64(chain.findLastestSideChainHeight() - chain.ethConfig.BlockConfig)
	}

}

func (chain *EthToPoly) findLastestSideChainHeight() uint64 {
	// try to get key
	var sideChainIdBytes [8]byte
	binary.LittleEndian.PutUint64(sideChainIdBytes[:], chain.ethConfig.SideChainId)
	contractAddress := utils.HeaderSyncContractAddress
	key := append([]byte(scom.CURRENT_HEADER_HEIGHT), sideChainIdBytes[:]...)
	// try to get storage
	result, err := chain.polySdk.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		log.Fatalf("findLastestSideChainHeight failed:%v", err)
	}
	if result == nil || len(result) == 0 {
		return 0
	} else {
		return binary.LittleEndian.Uint64(result)
	}
}

func (chain *EthToPoly) commitProof(height uint32, proof []byte, value []byte, headerOrCrossChainMsg []byte, txhash []byte) (string, error) {
	// log.Infof("commit proof, height: %d, proof: %s, value: %s, txhash: %s", height, string(proof), hex.EncodeToString(value), hex.EncodeToString(txhash))
	tx, err := chain.polySdk.Native.Ccm.ImportOuterTransfer(
		chain.ethConfig.SideChainId,
		value,
		height,
		proof,
		common.Hex2Bytes(chain.signer.Address.ToHexString()),
		headerOrCrossChainMsg,
		chain.signer)
	if err != nil {
		log.Fatalf("ImportOuterTransfer failed:%v", err)
	}

	log.Infof("commitProof - send transaction to poly chain: ( poly_txhash: %s, eth_txhash: %s, height: %d )",
		tx.ToHexString(), common.BytesToHash(txhash).String(), height)
	return tx.ToHexString(), nil

}

func (chain *EthToPoly) findLatestPolyEpochHeight() uint32 {
	address := common.HexToAddress(chain.ethConfig.ECCDContractAddress)
	instance, err := eccd_abi.NewEthCrossChainData(address, chain.clients[chain.idx])
	if err != nil {
		log.Fatalf("eccd_abi.NewEthCrossChainData failed:%v", err)
		return 0
	}

	height, err := instance.GetCurEpochStartHeight(nil)
	if err != nil {
		log.Fatalf("EthToPoly instance.GetCurEpochStartHeight failed:%v", err)
	}

	return uint32(height)
}

func (chain *EthToPoly) isHeaderEpoch(hdr *polytypes.Header) (bool, []byte, error) {
	client := chain.clients[chain.idx]
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(hdr.ConsensusPayload, blkInfo); err != nil {
		return false, nil, fmt.Errorf("vconfig.VbftBlockInfo json.Unmarshal error: %s", err)
	}
	if hdr.NextBookkeeper == common1.ADDRESS_EMPTY || blkInfo.NewChainConfig == nil {
		return false, nil, nil
	}

	eccdAddr := common.HexToAddress(chain.ethConfig.ECCDContractAddress)
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
