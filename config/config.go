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
	MySQLConfig    MySQLConfig
	PolyConfig     PolyConfig
	CurveConfig    EthConfig
	BSCConfig      EthConfig
	EthConfig      EthConfig
	HecoConfig     EthConfig
	OKConfig       EthConfig
	BridgeConfig   BridgeConfig
	GasPrice       *big.Int
	Print          bool
	SkippedSenders []string
	sync.Once
	BorConfig        EthConfig
	WhitelistMethods []string
	Force            bool
	CheckMerkleRoot  bool
	whitelistMethods map[string]bool
}

func (c *Config) IsEth(chainID uint64) bool {
	return c.EthConfig.SideChainId == chainID
}

func (c *Config) IsOK(chainID uint64) bool {
	return c.OKConfig.SideChainId == chainID
}

func (c *Config) IsWhitelistMethod(method string) bool {
	c.Do(func() {
		c.whitelistMethods = map[string]bool{}
		for _, m := range c.WhitelistMethods {
			c.whitelistMethods[m] = true
		}
	})

	return c.whitelistMethods[method]
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
	sync.Once
	SideChainId         uint64
	RestURL             []string
	TMRestURL           []string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
	BlockConfig         uint64
	SkippedSenders      []string
	skipped             map[common.Address]bool
}

func (c *EthConfig) ShouldSkip(addr common.Address) bool {
	c.Do(func() {
		skipped := make(map[common.Address]bool)
		for _, sender := range c.SkippedSenders {
			skipped[common.HexToAddress(sender)] = true
		}

		c.skipped = skipped
	})

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
