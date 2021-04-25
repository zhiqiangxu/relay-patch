package tx

import (
	"strconv"
	"sync"
	"time"

	"github.com/go-xorm/xorm"
	"github.com/zhiqiangxu/relay-patch/pkg/log"
	"github.com/zhiqiangxu/util"
)

// Filter for tx
type Filter struct {
	mysql        *xorm.Engine
	ethToPolyChs map[uint64]chan string
	polyToEthChs map[uint64]chan string
	doneCh       chan struct{}
}

// NewFilter ...
func NewFilter(
	mysql *xorm.Engine,
	ethToPolyChs map[uint64]chan string,
	polyToEthChs map[uint64]chan string) *Filter {
	return &Filter{mysql: mysql, ethToPolyChs: ethToPolyChs, polyToEthChs: polyToEthChs, doneCh: make(chan struct{})}
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
		for _, crossTx := range list {
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

func (f *Filter) queryCrossTxInfo() (list []*CrossTxInfo, err error) {

	results, err := f.mysql.QueryString("select a.chain_id src_chain_id,a.dst_chain_id,a.hash src_hash,c.hash poly_hash,a.time from src_transactions a join wrapper_transactions b on a.hash=b.hash left join poly_transactions c on a.hash=c.src_hash where b.status!=0 and if((a.chain_id in (6,7,10) and c.hash is null and UNIX_TIMESTAMP()>a.time+300) or (a.dst_chain_id in (6,7,10) and c.hash is not null and UNIX_TIMESTAMP()>c.time+300) or (a.chain_id=2 and c.hash is null and UNIX_TIMESTAMP()>a.time+1800) or (a.dst_chain_id=2 and c.hash is not null and UNIX_TIMESTAMP()>c.time+1800),true,false)")
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
