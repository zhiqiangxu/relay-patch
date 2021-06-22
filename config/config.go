package config

import (
	"encoding/json"
	"io/ioutil"
	"math/big"
)

// Config ...
type Config struct {
	MySQLConfig  MySQLConfig
	PolyConfig   PolyConfig
	CurveConfig  EthConfig
	BSCConfig    EthConfig
	EthConfig    EthConfig
	HecoConfig   EthConfig
	OKConfig     EthConfig
	BridgeConfig BridgeConfig
	GasPrice     *big.Int
	Force        bool
	Print        bool
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
	SideChainId         uint64
	RestURL             []string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
	BlockConfig         uint64
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
