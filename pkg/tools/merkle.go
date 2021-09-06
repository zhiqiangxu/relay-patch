package tools

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/polynetwork/poly/common"
)

const (
	LEFT byte = iota
	RIGHT
)

func MerkleRoot(path []byte, root []byte) ([]byte, error) {
	source := common.NewZeroCopySource(path)
	value, eof := source.NextVarBytes()
	if eof {
		return nil, errors.New("read bytes error")
	}
	hash := HashLeaf(value)
	size := int((source.Size() - source.Pos()) / (common.UINT256_SIZE + 1))
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, errors.New("read byte error")
		}
		v, eof := source.NextHash()
		if eof {
			return nil, errors.New("read hash error")
		}
		if f == LEFT {
			hash = HashChildren(v, hash)
		} else {
			hash = HashChildren(hash, v)
		}
	}

	if !bytes.Equal(hash[:], root) {
		return hash[:], fmt.Errorf("expect root is not equal actual root, expect:%x, actual:%x", hash, root)
	}
	return hash[:], nil
}

func HashLeaf(data []byte) common.Uint256 {
	tmp := append([]byte{0}, data...)
	return sha256.Sum256(tmp)
}

func HashChildren(left, right common.Uint256) common.Uint256 {
	data := append([]byte{1}, left[:]...)
	data = append(data, right[:]...)
	return sha256.Sum256(data)
}
