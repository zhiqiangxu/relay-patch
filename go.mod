module github.com/zhiqiangxu/relay-patch

go 1.15

require (
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/cosmos/cosmos-sdk v0.39.2
	github.com/ethereum/go-ethereum v1.10.2
	github.com/go-sql-driver/mysql v1.5.0
	github.com/go-xorm/xorm v0.7.9
	github.com/gogo/protobuf v1.3.1
	github.com/okex/exchain v0.18.4
	github.com/okex/exchain-go-sdk v0.18.2
	github.com/oklog/run v1.0.0
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/poly v0.0.0-20210112063446-24e3d053e9d6
	github.com/polynetwork/poly-bridge/bridgesdk v0.0.2
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/polynetwork/poly-io-test v0.0.0-20200819093740-8cf514b07750 // indirect
	github.com/tendermint/tendermint v0.33.9
	github.com/zhiqiangxu/util v0.0.0-20210114025214-5f087283a7a6
)

replace (
	github.com/cosmos/cosmos-sdk => github.com/okex/cosmos-sdk v0.39.2-exchain3
	github.com/ethereum/go-ethereum => github.com/zhiqiangxu/go-ethereum v0.0.0-20210513053854-b16fac27e406
	github.com/tendermint/iavl => github.com/okex/iavl v0.14.3-exchain
	github.com/tendermint/tendermint => github.com/okex/tendermint v0.33.9-exchain2
)
