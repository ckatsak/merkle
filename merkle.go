//TODO Documentation
package merkle

import (
	"crypto"
	"fmt"
)

//TODO Documentation
type Datum interface {
	Serialize() []byte
}

//TODO Documentation
type ErrHashUnavailable struct{}

func (ErrHashUnavailable) Error() string {
	return fmt.Sprintf("Hash Algorithm Unavailable")
}

//TODO Documentation
type Tree struct {
	hash crypto.Hash
	mns  [][][]byte
	tls  []treeLeaf
}

type treeLeaf struct {
	digest []byte
	datum  Datum
}

//TODO Documentation
func (t *Tree) Height() int {
	return len(t.mns) + 1
}

//TODO Documentation
func (t *Tree) MerkleSize() (merkleSize int) {
	for i := 0; i < len(t.mns); i++ {
		for j := 0; j < len(t.mns[i]); j++ {
			merkleSize += 1
		}
	}
	return
}

//TODO Documentation
func (t *Tree) NumLeaves() (numLeaves int) {
	return len(t.tls)
}

//TODO Documentation
func NewTree(hash crypto.Hash, data ...Datum) (*Tree, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable{}
	}
	h := hash.New()
	tls := make([]treeLeaf, 0, len(data))
	for _, datum := range data {
		h.Reset()
		h.Write(datum.Serialize())
		tls = append(tls, treeLeaf{
			digest: h.Sum(nil),
			datum:  datum,
		})
	}
	numMerkleNodes, rowSizes := calculateMerkleNumbers(len(data))
	mnsSeq := make([]byte, 0, h.Size()*numMerkleNodes)
	mns := make([][][]byte, len(rowSizes))
	// mns[0][0] --> ROOT
	// mns[1][0] mns[1][1]
	// mns[2][0] mns[2][1] mns[2][2] mns[2][3]
	// mns[3][0] mns[3][1] mns[3][2] mns[3][3] mns[3][4] mns[3][5] mns[3][6] mns[3][7]
	//  . . .
	mnCount := 0
	for i := 0; i < len(rowSizes); i++ {
		mns[i] = make([][]byte, rowSizes[len(rowSizes)-1-i])
		for j := 0; j < rowSizes[len(rowSizes)-1-i]; j++ {
			mns[i][j] = mnsSeq[mnCount*h.Size() : (mnCount+1)*h.Size()]
			if i == len(rowSizes)-1 {
				h.Reset()
				h.Write(tls[2*j].digest)
				if 2*j+1 < len(tls) {
					h.Write(tls[2*j+1].digest)
				}
				digest := h.Sum(nil)
				copy(mns[i][j], digest)
			}
			mnCount += 1
		}
	}
	for i := len(rowSizes) - 2; i >= 0; i-- {
		for j := 0; j < rowSizes[len(rowSizes)-1-i]; j++ {
			h.Reset()
			h.Write(mns[i+1][2*j])
			if 2*j+1 < len(mns[i+1]) {
				h.Write(mns[i+1][2*j+1])
			}
			digest := h.Sum(nil)
			copy(mns[i][j], digest)
		}
	}

	return &Tree{
		hash: hash,
		mns:  mns,
		tls:  tls,
	}, nil
}

// TODO: Implementation
// TODO: Documentation
func (t *Tree) Verify(datum Datum) (bool, error) {
	if datum == nil {
		return false, fmt.Errorf("nil datum")
	}
	h := t.hash.New()
	h.Reset()
	h.Write(datum.Serialize())
	datumDigest := h.Sum(nil)
}

func calculateMerkleNumbers(numLeaves int) (numMerkleNodes int, mns []int) {
	for numLeaves > 1 {
		if numLeaves%2 == 1 {
			numLeaves = (numLeaves / 2) + 1
		} else {
			numLeaves = numLeaves / 2
		}
		mns = append(mns, numLeaves)
		numMerkleNodes += numLeaves
	}
	return
}
