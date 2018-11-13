// Package merkle implements a very simple, immutable, in-memory, "hash
// function-agnostic" and "stored data-agnostic" merkle tree.
package merkle

import (
	"bytes"
	"crypto"
	"sort"
)

//TODO Documentation
type Datum interface {
	Serialize() []byte
}

//TODO Documentation
type ErrHashUnavailable struct{}

func (ErrHashUnavailable) Error() string {
	return "Hash Algorithm Unavailable"
}

//TODO Documentation
type ErrNoData struct{}

func (ErrNoData) Error() string {
	return "Nonexistent Data"
}

//TODO Documentation
type Tree struct {
	hash crypto.Hash
	mns  [][][]byte
	tls  []treeLeaf
}

//TODO Documentation
func (t *Tree) Height() int {
	return len(t.mns) + 1
}

//TODO Documentation
func (t *Tree) Size() int {
	return t.MerkleSize() + t.NumLeaves()
}

//TODO Documentation
func (t *Tree) MerkleSize() (merkleSize int) {
	for i := range t.mns {
		merkleSize += len(t.mns[i])
	}
	return
}

//TODO Documentation
func (t *Tree) NumLeaves() (numLeaves int) {
	return len(t.tls)
}

//TODO Documentation
func (t *Tree) MerkleRoot() []byte {
	return t.mns[0][0]
}

//TODO Documentation
func NewTree(hash crypto.Hash, data ...Datum) (*Tree, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable{}
	}
	h := hash.New()

	if len(data) == 0 {
		return nil, ErrNoData{}
	}

	// Create the leaves.
	tls := make([]treeLeaf, 0, len(data))
	for i := range data {
		serializedDatum := data[i].Serialize()
		h.Reset()
		h.Write(serializedDatum)
		tls = append(tls, treeLeaf{
			digest:    h.Sum(nil),
			datum:     serializedDatum,
			orderedID: uint(i),
		})
	}
	sort.Slice(tls, func(i, j int) bool {
		return bytes.Compare(tls[i].datum, tls[j].datum) == -1
	})

	// Create the merkle nodes.
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

//TODO Documentation
func (t *Tree) VerifyDigest(digest []byte) (bool, error) {
	for leafIndex := range t.tls {
		if bytes.Compare(digest, t.tls[leafIndex].datum) == 0 {
			return t.verify(leafIndex)
		}
	}
	return false, ErrNoData{}
}

//TODO Documentation
func (t *Tree) VerifyOrderedID(orderedID uint) (bool, error) {
	for leafIndex := range t.tls {
		if t.tls[leafIndex].orderedID == orderedID {
			return t.verify(leafIndex)
		}
	}
	return false, ErrNoData{}
}

//TODO Documentation
func (t *Tree) VerifySerializedDatum(serializedDatum []byte) (bool, error) {
	leafIndex := sort.Search(len(t.tls), func(i int) bool {
		return bytes.Compare(t.tls[i].datum, serializedDatum) == 0
	})
	if leafIndex < len(t.tls) {
		return t.verify(leafIndex)
	}
	return false, ErrNoData{}
}

//TODO Documentation
func (t *Tree) VerifyDatum(datum Datum) (bool, error) {
	if datum == nil {
		return false, ErrNoData{}
	}
	return t.VerifySerializedDatum(datum.Serialize())
}

// TODO Implementation
func (t *Tree) verify(leafIndex int) (bool, error) {
	panic("Unimplemented")
	currentLevel := len(t.mns)

	h := t.hash.New()
	h.Reset()
	h.Write(t.tls[leafIndex].datum)
	leafDigest := h.Sum(nil)

	_, _ = leafDigest, currentLevel

	return false, nil
}

//TODO Implementation
//
//TODO Documentation
func (t *Tree) AppendAndReconstruct(data ...Datum) {
	panic("Unimplemented")
}

//TODO Implementation
//
//TODO Documentation
func (t *Tree) DeleteAndReconstruct(data ...Datum) {
	panic("Unimplemented")
}

//TODO Implementation
//
//TODO Documentation
type TreeLeaf struct {
	Digest          []byte
	SerializedDatum []byte
}

//TODO Implementation
//
//TODO Documentation
func (t *Tree) Leaves() []TreeLeaf {
	panic("Unimplemented")
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

type treeLeaf struct {
	digest    []byte
	datum     []byte
	orderedID uint
}
