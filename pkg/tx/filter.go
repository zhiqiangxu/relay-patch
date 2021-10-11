package tx

import (
	"strconv"
	"sync"
	"time"

	"github.com/go-xorm/xorm"
	"github.com/zhiqiangxu/relay-patch/config"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/util"
)

// Filter for tx
type Filter struct {
	mysql        *xorm.Engine
	ethToPolyChs map[uint64]chan string
	polyToEthChs map[uint64]chan string
	doneCh       chan struct{}
	conf         *config.Config
}

// NewFilter ...
func NewFilter(
	mysql *xorm.Engine,
	ethToPolyChs map[uint64]chan string,
	polyToEthChs map[uint64]chan string,
	conf *config.Config) *Filter {
	return &Filter{mysql: mysql, ethToPolyChs: ethToPolyChs, polyToEthChs: polyToEthChs, doneCh: make(chan struct{}), conf: conf}
}

// CrossTxInfo ...
type CrossTxInfo struct {
	SrcTxHash  string
	SrcChainID uint64
	PolyTxHash string
	DstChainID uint64
}

// Start ...
func (f *Filter) Start() {

	for {
		list, err := f.queryCrossTxInfo()
		if err != nil {
			log.Errorf("f.queryCrossTxInfo failed:%v", err)
			time.Sleep(time.Second)
			continue
		}

		if len(list) == 0 {
			break
		}

		log.Infof("found %d cross tx", len(list))

		var wg sync.WaitGroup
		for i := range list {
			crossTx := list[i]
			if crossTx.PolyTxHash == "" {
				targetCh := f.ethToPolyChs[crossTx.SrcChainID]
				if targetCh == nil {
					log.Fatalf("ethToPoly (src_chain_id %d dst_chain_id %d) targetCh not found for chain:%d", crossTx.SrcChainID, crossTx.DstChainID, crossTx.SrcChainID)
				}
				util.GoFunc(&wg, func() {
					select {
					case targetCh <- crossTx.SrcTxHash:
					case <-f.doneCh:
					}
				})
			} else {
				targetCh := f.polyToEthChs[crossTx.DstChainID]
				if targetCh == nil {
					log.Fatalf("polyToEth (src_chain_id %d dst_chain_id %d) targetCh not found for chain:%d", crossTx.SrcChainID, crossTx.DstChainID, crossTx.DstChainID)
				}
				util.GoFunc(&wg, func() {
					select {
					case targetCh <- crossTx.PolyTxHash:
					case <-f.doneCh:
					}
				})
			}
		}
		wg.Wait()

		break
	}

	log.Infof("all jobs done, quiting")
	time.Sleep(time.Second * 60)
	log.Infof("all jobs done, quited")

}

// Stop ...
func (f *Filter) Stop() {
	close(f.doneCh)
}

const TX_QUERY = `
SELECT a.chain_id src_chain_id,
       a.dst_chain_id,
       a.hash src_hash,
       c.hash poly_hash,
       a.time
FROM src_transactions a
JOIN wrapper_transactions b ON a.hash=b.hash
LEFT JOIN poly_transactions c ON a.hash=c.src_hash
JOIN wrapper_transactions d ON a.hash=d.hash
WHERE b.status!=0 AND (UNIX_TIMESTAMP() < a.time + ?)
  AND if((a.chain_id in (6, 7, 10, 12)
          AND c.hash IS NULL
          AND UNIX_TIMESTAMP()>a.time+180)
         OR (a.dst_chain_id in (6, 7, 10, 12, 17)
             AND c.hash IS NOT NULL
             AND UNIX_TIMESTAMP()>c.time+180)
         OR (a.chain_id in (2, 17)
             AND c.hash IS NULL
             AND UNIX_TIMESTAMP()>a.time+600)
         OR (a.dst_chain_id in (2, 19)
             AND c.hash IS NOT NULL
             AND UNIX_TIMESTAMP()>c.time+600),TRUE, FALSE)
UNION ALL
SELECT a.chain_id AS src_chain_id,
       a.dst_chain_id AS dst_chain_id,
       a.hash AS src_hash,
       b.hash AS poly_hash,
       a.time AS TIME
FROM src_transactions a
LEFT JOIN poly_transactions b ON a.hash = b.src_hash
LEFT JOIN dst_transactions c ON b.hash = c.poly_hash
WHERE a.chain_id = 10 AND (UNIX_TIMESTAMP() < a.time + ?)
  AND IF((b.hash IS NULL
          AND UNIX_TIMESTAMP()>a.time+180)
         OR (b.hash IS NOT NULL
             AND c.hash IS NULL
             AND ((a.dst_chain_id in (6, 7, 10, 12, 17)
                   AND UNIX_TIMESTAMP()>b.time+180)
                  OR (a.dst_chain_id in (2, 19) 
                      AND UNIX_TIMESTAMP()>b.time+600))),TRUE, FALSE)`

func (f *Filter) queryCrossTxInfo() (list []*CrossTxInfo, err error) {
	days := f.conf.FilterDays
	if days == 0 {
		days = 3
	}

	/*
		results, err := f.mysql.QueryString(
			`select a.chain_id src_chain_id,a.dst_chain_id,a.hash src_hash,c.hash poly_hash,a.time from src_transactions a join wrapper_transactions b on a.hash=b.hash left join poly_transactions c on a.hash=c.src_hash join wrapper_transactions d on a.hash=d.hash where b.status!=0 and if((a.chain_id in (6,7,10,12) and c.hash is null and UNIX_TIMESTAMP()>a.time+180) or (a.dst_chain_id in (6,7,10,12,17) and c.hash is not null and UNIX_TIMESTAMP()>c.time+180) or (a.chain_id in (2,17) and c.hash is null and UNIX_TIMESTAMP()>a.time+600) or (a.dst_chain_id=2 and c.hash is not null and UNIX_TIMESTAMP()>c.time+600),true,false)
		union all
			select a.chain_id as src_chain_id, a.dst_chain_id as dst_chain_id, a.hash as src_hash, b.hash as poly_hash, a.time as time from src_transactions a left join poly_transactions b on a.hash = b.src_hash left join dst_transactions c on b.hash = c.poly_hash where a.chain_id = 10 and IF((b.hash is null and UNIX_TIMESTAMP()>a.time+180) or (b.hash is not null and c.hash is null and ((a.dst_chain_id in (6,7,10,12,17) and UNIX_TIMESTAMP()>b.time+180) or (a.dst_chain_id=2 and UNIX_TIMESTAMP()>b.time+600) ) ),true,false) and UNIX_TIMESTAMP()<a.time+86400`)
	*/
	period := days * 24 * 3600
	results, err := f.mysql.QueryString(TX_QUERY, period, period)
	if err != nil {
		return
	}

	for _, result := range results {
		var (
			srcChainID, dstChainID int
		)
		srcChainID, err = strconv.Atoi(result["src_chain_id"])
		if err != nil {
			return
		}
		dstChainID, err = strconv.Atoi(result["dst_chain_id"])
		if err != nil {
			return
		}
		list = append(list, &CrossTxInfo{
			SrcTxHash:  result["src_hash"],
			SrcChainID: uint64(srcChainID),
			PolyTxHash: result["poly_hash"],
			DstChainID: uint64(dstChainID),
		})
	}
	return
}
