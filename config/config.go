package config

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// Config ...
type Config struct {
	MySQLConfig     MySQLConfig
	PolyConfig      PolyConfig
	CurveConfig     EthConfig
	BSCConfig       EthConfig
	EthConfig       EthConfig
	HecoConfig      EthConfig
	OKConfig        EthConfig
	BorConfig       EthConfig
	BridgeConfig    BridgeConfig
	GasPrice        *big.Int
	Force           bool
	CheckMerkleRoot bool
	Print           bool
}

func (c *Config) IsEth(chainID uint64) bool {
	return c.EthConfig.SideChainId == chainID
}

// BridgeConfig ...
type BridgeConfig struct {
	RestURL [][]string
}

// MySQLConfig for mysql
type MySQLConfig struct {
	ConnectionString string
	ConnMaxLifetime  int
	MaxOpenConn      int
	MaxIdleConn      int
	ShowSQL          bool
	Slaves           []MySQLConfig
}

// PolyConfig ...
type PolyConfig struct {
	RestURL                 string
	EntranceContractAddress string
	WalletFile              string
	WalletPwd               string
}

// EthConfig ...
type EthConfig struct {
	sync.Mutex
	SideChainId         uint64
	RestURL             []string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
	BlockConfig         uint64
	SkippedSenders      []string
	skipped             map[common.Address]bool
}

func (c *EthConfig) ShouldSkip(addr common.Address) bool {
	if c.skipped != nil {
		return c.skipped[addr]
	}

	c.Lock()
	defer c.Unlock()

	if c.skipped != nil {
		return c.skipped[addr]
	}

	skipped := make(map[common.Address]bool)
	for _, sender := range c.SkippedSenders {
		skipped[common.HexToAddress(sender)] = true
	}

	c.skipped = skipped

	return c.skipped[addr]
}

// LoadConfig ...
func LoadConfig(confFile string) (config *Config, err error) {
	jsonBytes, err := ioutil.ReadFile(confFile)
	if err != nil {
		return
	}

	config = &Config{}
	err = json.Unmarshal(jsonBytes, config)
	return
}
