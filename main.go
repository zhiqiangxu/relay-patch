package main

import (
	"context"
	"flag"
	"math/big"
	"strings"
	"time"

	"poly_bridge_sdk"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/oklog/run"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/zhiqiangxu/relay-patch/config"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/relay-patch/pkg/relay"
	"github.com/zhiqiangxu/relay-patch/pkg/storage"
	"github.com/zhiqiangxu/relay-patch/pkg/tools"
	txPkg "github.com/zhiqiangxu/relay-patch/pkg/tx"
)

var confFile string
var tx string
var chain uint64
var force bool
var price string

func init() {
	flag.StringVar(&confFile, "conf", "./config.json", "configuration file path")
	flag.StringVar(&tx, "tx", "", "specify tx hash")
	flag.Uint64Var(&chain, "chain", 0, "specify chain ID")
	flag.BoolVar(&force, "force", false, "force transaction")
	flag.StringVar(&price, "price", "", "gas price")

	flag.Parse()
}

func setUpEthClientAndKeyStore(ethConfig *config.EthConfig) ([]*ethclient.Client, *tools.EthKeyStore) {
	var clients []*ethclient.Client
	for _, node := range ethConfig.RestURL {
		client, err := ethclient.Dial(node)
		if err != nil {
			log.Fatalf("ethclient.Dial failed:%v", err)
		}

		clients = append(clients, client)
	}

	start := time.Now()
	chainID, err := clients[0].ChainID(context.Background())
	if err != nil {
		log.Fatalf("clients[0].ChainID failed:%v", err)
	}
	log.Infof("SideChain %d ChainID() took %v", ethConfig.SideChainId, time.Now().Sub(start).String())

	ks := tools.NewEthKeyStore(ethConfig.KeyStorePath, ethConfig.KeyStorePwdSet, chainID)

	return clients, ks
}

func setUpEthToPoly(ethToPolyCh chan string, polySdk *sdk.PolySdk,
	signer *sdk.Account,
	clients []*ethclient.Client,
	ethConfig *config.EthConfig,
	conf *config.Config) []*relay.EthToPoly {

	var workers []*relay.EthToPoly
	for i := 0; i < 5; i++ {
		workers = append(workers, relay.NewEthToPoly(ethToPolyCh, polySdk, signer, clients, ethConfig, conf))
	}

	return workers
}

func setUpPolyToEth(clients []*ethclient.Client, ks *tools.EthKeyStore, polyToEthWorkCh chan string, polySdk *sdk.PolySdk, bridgeSdk *poly_bridge_sdk.BridgeFeeCheck, ethConfig *config.EthConfig, polyConfig *config.PolyConfig, conf *config.Config) []*relay.PolyToEth {

	var workers []*relay.PolyToEth
	for _, account := range ks.GetAccounts() {
		worker := relay.NewPolyToEth(polyToEthWorkCh, polySdk, bridgeSdk, clients, ethConfig, polyConfig, conf, account, ks)
		workers = append(workers, worker)
	}

	return workers
}

func main() {

	log.InitLog(log.InfoLog, "./Log/", log.Stdout)

	conf, err := config.LoadConfig(confFile)
	if err != nil {
		log.Fatalf("LoadConfig fail:%v", err)
	}

	if force {
		conf.Force = true
	}
	if price != "" {
		gasPrice := big.NewInt(0)
		gasPrice, ok := gasPrice.SetString(price, 10)
		if !ok {
			log.Fatalf("invalid gas price:%v", price)
		}
		conf.GasPrice = gasPrice
	}

	// {
	// 	confBytes, _ := json.MarshalIndent(conf, "", "    ")
	// 	fmt.Println("conf", string(confBytes))
	// }

	polySdk := sdk.NewPolySdk()
	err = setUpPoly(polySdk, conf.PolyConfig.RestURL)
	if err != nil {
		log.Fatalf("setUpPoly failed: %v", err)
	}

	wallet, err := polySdk.OpenWallet(conf.PolyConfig.WalletFile)
	if err != nil {
		log.Fatalf("polySdk.OpenWallet failed: %v", err)
	}
	signer, err := wallet.GetDefaultAccount([]byte(conf.PolyConfig.WalletPwd))
	if err != nil {
		log.Fatalf("wallet.GetDefaultAccount failed: %v", err)
	}

	ethToPolyChs := make(map[uint64]chan string)
	polyToEthChs := make(map[uint64]chan string)
	ethToPolyChs[conf.BSCConfig.SideChainId] = make(chan string)
	ethToPolyChs[conf.HecoConfig.SideChainId] = make(chan string)
	ethToPolyChs[conf.CurveConfig.SideChainId] = make(chan string)
	ethToPolyChs[conf.EthConfig.SideChainId] = make(chan string)
	ethToPolyChs[conf.OKConfig.SideChainId] = make(chan string)

	polyToEthChs[conf.BSCConfig.SideChainId] = make(chan string)
	polyToEthChs[conf.HecoConfig.SideChainId] = make(chan string)
	polyToEthChs[conf.CurveConfig.SideChainId] = make(chan string)
	polyToEthChs[conf.EthConfig.SideChainId] = make(chan string)
	polyToEthChs[conf.OKConfig.SideChainId] = make(chan string)

	bscClients, bscKS := setUpEthClientAndKeyStore(&conf.BSCConfig)
	hecoClients, hecoKS := setUpEthClientAndKeyStore(&conf.HecoConfig)
	curveClients, curveKS := setUpEthClientAndKeyStore(&conf.CurveConfig)
	ethClients, ethKS := setUpEthClientAndKeyStore(&conf.EthConfig)
	okClients, okKS := setUpEthClientAndKeyStore(&conf.OKConfig)

	bscToPolyWorkers := setUpEthToPoly(ethToPolyChs[conf.BSCConfig.SideChainId], polySdk, signer, bscClients, &conf.BSCConfig, conf)
	hecoToPolyWorkers := setUpEthToPoly(ethToPolyChs[conf.HecoConfig.SideChainId], polySdk, signer, hecoClients, &conf.HecoConfig, conf)
	curveToPolyWorkers := setUpEthToPoly(ethToPolyChs[conf.CurveConfig.SideChainId], polySdk, signer, curveClients, &conf.CurveConfig, conf)
	ethToPolyWorkers := setUpEthToPoly(ethToPolyChs[conf.EthConfig.SideChainId], polySdk, signer, ethClients, &conf.EthConfig, conf)
	okToPolyWorkers := setUpEthToPoly(ethToPolyChs[conf.OKConfig.SideChainId], polySdk, signer, okClients, &conf.OKConfig, conf)

	bridgeSdk := poly_bridge_sdk.NewBridgeFeeCheck(conf.BridgeConfig.RestURL, 5)

	polyToBscWorkers := setUpPolyToEth(bscClients, bscKS, polyToEthChs[conf.BSCConfig.SideChainId], polySdk, bridgeSdk, &conf.BSCConfig, &conf.PolyConfig, conf)
	polyToHecoWorkers := setUpPolyToEth(hecoClients, hecoKS, polyToEthChs[conf.HecoConfig.SideChainId], polySdk, bridgeSdk, &conf.HecoConfig, &conf.PolyConfig, conf)
	polyToCurveWorkers := setUpPolyToEth(curveClients, curveKS, polyToEthChs[conf.CurveConfig.SideChainId], polySdk, bridgeSdk, &conf.CurveConfig, &conf.PolyConfig, conf)
	polyToEthWorkers := setUpPolyToEth(ethClients, ethKS, polyToEthChs[conf.EthConfig.SideChainId], polySdk, bridgeSdk, &conf.EthConfig, &conf.PolyConfig, conf)
	polyToOKWorkers := setUpPolyToEth(okClients, okKS, polyToEthChs[conf.OKConfig.SideChainId], polySdk, bridgeSdk, &conf.OKConfig, &conf.PolyConfig, conf)

	if tx != "" {
		txes := strings.Split(tx, ",")
		for _, txHash := range txes {
			var (
				targetWorkersForEthToPoly []*relay.EthToPoly
				targetWorkersForPolyToEth []*relay.PolyToEth
				toChainID                 uint64
				polyTxHash                string
			)
			switch chain {
			case conf.BSCConfig.SideChainId:
				targetWorkersForEthToPoly = bscToPolyWorkers
			case conf.HecoConfig.SideChainId:
				targetWorkersForEthToPoly = hecoToPolyWorkers
			case conf.CurveConfig.SideChainId:
				targetWorkersForEthToPoly = curveToPolyWorkers
			case conf.EthConfig.SideChainId:
				targetWorkersForEthToPoly = ethToPolyWorkers
			case conf.OKConfig.SideChainId:
				targetWorkersForEthToPoly = okToPolyWorkers
			case 0:
				// handle poly tx hash
				merkleValue, _, _ := relay.GetKeyParams(polySdk, &conf.PolyConfig, txHash, 0)
				if merkleValue == nil {
					log.Errorf("merkle value empty for poly hash %s", tx)
				}
				toChainID = merkleValue.MakeTxParam.ToChainID
				polyTxHash = txHash
				goto HANDLE_POLY_TX
			default:
				log.Fatalf("unsupported chainID:%d", chain)
			}

			toChainID, polyTxHash = targetWorkersForEthToPoly[0].MonitorTx(txHash)

			if polyTxHash == "" {
				return
			}

		HANDLE_POLY_TX:

			log.Infof("toChainID:%d poly hash:%s", toChainID, polyTxHash)

			polyTxHeight, err := polySdk.GetBlockHeightByTxHash(polyTxHash)
			if err != nil {
				log.Fatalf("polySdk.GetBlockHeightByTxHash failed:%v", err)
			}

			waitPolyHeight(polySdk, polyTxHeight+1)

			switch toChainID {
			case conf.BSCConfig.SideChainId:
				targetWorkersForPolyToEth = polyToBscWorkers
			case conf.HecoConfig.SideChainId:
				targetWorkersForPolyToEth = polyToHecoWorkers
			case conf.CurveConfig.SideChainId:
				targetWorkersForPolyToEth = polyToCurveWorkers
			case conf.EthConfig.SideChainId:
				targetWorkersForPolyToEth = polyToEthWorkers
			case conf.OKConfig.SideChainId:
				targetWorkersForPolyToEth = polyToOKWorkers
			default:
				log.Fatalf("unsupported chainID:%d", toChainID)
			}

			targetWorkersForPolyToEth[0].SendTx(polyTxHash)
		}

		return

	}

	mysql, err := storage.NewMySQL(conf.MySQLConfig)
	if err != nil {
		log.Fatalf("storage.NewMySQL failed:%v", err)
	}

	filter := txPkg.NewFilter(mysql, ethToPolyChs, polyToEthChs)

	var g run.Group

	g.Add(func() error {
		filter.Start()
		return nil
	}, func(error) {
		filter.Stop()
	})

	toPolyWorkers := append(append(append(append(bscToPolyWorkers, hecoToPolyWorkers...), curveToPolyWorkers...), ethToPolyWorkers...), okToPolyWorkers...)
	for i := range toPolyWorkers {
		worker := toPolyWorkers[i]
		g.Add(func() error {
			worker.Start()
			return nil
		}, func(error) {
			worker.Stop()
		})
	}
	fromPolyWorkers := append(append(append(append(polyToBscWorkers, polyToHecoWorkers...), polyToCurveWorkers...), polyToEthWorkers...), polyToOKWorkers...)
	for i := range fromPolyWorkers {
		worker := fromPolyWorkers[i]
		g.Add(func() error {
			worker.Start()
			return nil
		}, func(error) {
			worker.Stop()
		})
	}

	go func() {
		err := g.Run()
		log.Fatalf("run.Group finished:%v", err)
		for _, workCh := range ethToPolyChs {
			close(workCh)
		}
		for _, workCh := range polyToEthChs {
			close(workCh)
		}
	}()

	for _, workCh := range ethToPolyChs {
		<-workCh
	}
	for _, workCh := range polyToEthChs {
		<-workCh
	}
	return
}

func setUpPoly(polySdk *sdk.PolySdk, rpcAddr string) error {
	polySdk.NewRpcClient().SetAddress(rpcAddr)
	hdr, err := polySdk.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	polySdk.SetChainId(hdr.ChainID)
	return nil
}

func waitPolyHeight(polySdk *sdk.PolySdk, height uint32) {
	for {
		currentHeight, err := polySdk.GetCurrentBlockHeight()
		if err != nil {
			log.Fatalf("polySdk.GetCurrentBlockHeight failed:%v", err)
		}
		if currentHeight >= height {
			break
		}
		log.Infof("wait poly height:%d, current height:%d", height, currentHeight)
		time.Sleep(time.Second)
	}

}
