module github.com/zhiqiangxu/relay-patch

go 1.15

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/ethereum/go-ethereum v1.10.2
	github.com/go-sql-driver/mysql v1.4.1
	github.com/go-xorm/xorm v0.7.9
	github.com/oklog/run v1.0.0
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/ontio/ontology-crypto v1.0.9
	github.com/polynetwork/poly v0.0.0-20210112063446-24e3d053e9d6
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/polynetwork/poly-io-test v0.0.0-20200819093740-8cf514b07750 // indirect
	github.com/zhiqiangxu/util v0.0.0-20210114025214-5f087283a7a6
)

replace (
	github.com/ethereum/go-ethereum => github.com/zhiqiangxu/go-ethereum v0.0.0-20210513053854-b16fac27e406
)
