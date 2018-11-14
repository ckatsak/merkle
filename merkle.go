// Package merkle implements a very simple, immutable, in-memory, "hash
// function-agnostic" and "stored data-agnostic" merkle tree.
package merkle

import (
	"bytes"
	"crypto"
	"sort"
)

// Datum is the interface that any piece of data has to implement so as to be
// able to be contained in the leaves of the merkle tree.
type Datum interface {
	// Serialize provides a serialized format of the entity.
	Serialize() []byte
}

type (
	// ErrHashUnavailable signifies that the requested hash function has
	// not been linked to the executable.
	ErrHashUnavailable struct{}

	// ErrNoData signifies that the piece of data requested is either nil
	// or not present in the merkle tree.
	ErrNoData struct{}
)

func (ErrHashUnavailable) Error() string {
	return "Hash Algorithm Unavailable"
}
func (ErrNoData) Error() string {
	return "Nonexistent Data"
}

type (
	// Tree is the exported struct to interact with the merkle tree.
	Tree struct {
		hash crypto.Hash
		mns  [][][]byte
		tls  []treeLeaf
	}

	treeLeaf struct {
		digest    []byte
		datum     []byte
		orderedID uint
	}
)

// Height returns the height of the merkle tree, including both its leaves and
// the merkle nodes.
func (t *Tree) Height() int {
	return len(t.mns) + 1
}

// Size returns the total number of nodes in the merkle tree, including both
// its leaves and the merkle nodes.
func (t *Tree) Size() int {
	return t.MerkleSize() + t.NumLeaves()
}

// MerkleSize returns the number of merkle nodes in the merkle trees, i.e. the
// total number of nodes in the merkle tree, excluding its leaves.
func (t *Tree) MerkleSize() (merkleSize int) {
	for i := range t.mns {
		merkleSize += len(t.mns[i])
	}
	return
}

// NumLeaves returns the number of leaves in the merkle tree.
func (t *Tree) NumLeaves() (numLeaves int) {
	return len(t.tls)
}

// MerkleRoot returns the hash digest of the root of the merkle tree.
func (t *Tree) MerkleRoot() []byte {
	return t.mns[0][0]
}

// NewTree creates a new merkle tree given one of the known hash functions and
// a bunch of data.
//
// It returns a non-nil error either if the requested hash function has not
// been linked to the executable, or if data are not given at all.
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

// VerifyDigest verifies that the given (leaf) hash digest is present in the
// merkle tree, in which case it returns true and a nil error value.
//
// It requires O(L) search among the leaves and O(log2(L)) hash calculations.
//
// If the given hash digest cannot be verified, VerifyDigest returns false.
//
// If the given hash digest cannot be found in one of the merkle tree's leaves,
// VerifyDigest returns false and a non-nil error value.
func (t *Tree) VerifyDigest(digest []byte) (bool, error) {
	for leafIndex := range t.tls {
		if bytes.Compare(digest, t.tls[leafIndex].datum) == 0 {
			return t.verify(leafIndex)
		}
	}
	return false, ErrNoData{}
}

// VerifyOrderedID verifies that the Datum with the given ordered ID (based on
// the order that the leaves were initially given) is present in the merkle
// tree, in which case it returns true and a nil error value.
//
// It requires O(L) search among the leaves and O(log2(L)) hash calculations.
//
// If the given hash digest cannot be verified, VerifyOrderedID returns false.
//
// If the given hash digest cannot be found in one of the merkle tree's leaves,
// VerifyOrderedID returns false and a non-nil error value.
func (t *Tree) VerifyOrderedID(orderedID uint) (bool, error) {
	for leafIndex := range t.tls {
		if t.tls[leafIndex].orderedID == orderedID {
			return t.verify(leafIndex)
		}
	}
	return false, ErrNoData{}
}

// VerifySerializedDatum verifies that the given Datum (given in its serialized
// format) is present in the merkle tree, in which case it returns true and a
// nil error value.
//
// It requires O(log2(L)) search among the leaves and O(log2(L)) hash
// calculations.
//
// If the given hash digest cannot be verified, VerifySerializedDatum returns
// false.
//
// If the given hash digest cannot be found in one of the merkle tree's leaves,
// VerifySerializedDatum returns false and a non-nil error value.
func (t *Tree) VerifySerializedDatum(serializedDatum []byte) (bool, error) {
	leafIndex := sort.Search(len(t.tls), func(i int) bool {
		return bytes.Compare(t.tls[i].datum, serializedDatum) >= 0
	})
	if leafIndex < len(t.tls) && bytes.Compare(t.tls[leafIndex].datum, serializedDatum) == 0 {
		return t.verify(leafIndex)
	}
	return false, ErrNoData{}
}

// VerifyDatum verifies that the given Datum is present in the merkle tree, in
// which case it returns true and a nil error value.
//
// It requires O(log2(L)) search among the leaves and O(log2(L)) hash
// calculations.
//
// If the given hash digest cannot be verified, VerifyDatum returns false.
//
// If the given hash digest cannot be found in one of the merkle tree's leaves,
// VerifyDatum returns false and a non-nil error value.
func (t *Tree) VerifyDatum(datum Datum) (bool, error) {
	if datum == nil {
		return false, ErrNoData{}
	}
	return t.VerifySerializedDatum(datum.Serialize())
}

func (t *Tree) verify(currentIndex int) (bool, error) {
	h := t.hash.New()
	h.Write(t.tls[currentIndex].datum)
	currentDigest := h.Sum(nil)

	var (
		siblingDigest, parentDigest []byte
		parentIndex                 int
		first, second               []byte
	)
	// Verify leaf.
	if currentIndex%2 == 0 {
		if currentIndex < len(t.tls)-1 {
			siblingDigest = t.tls[currentIndex+1].digest
		} else {
			siblingDigest = []byte{}
		}
		parentIndex = currentIndex / 2
		parentDigest = t.mns[len(t.mns)-1][parentIndex]
		first, second = currentDigest, siblingDigest
	} else {
		siblingDigest = t.tls[currentIndex-1].digest
		parentIndex = (currentIndex - 1) / 2
		parentDigest = t.mns[len(t.mns)-1][parentIndex]
		first, second = siblingDigest, currentDigest
	}
	h.Reset()
	h.Write(first)
	h.Write(second)
	if bytes.Compare(parentDigest, h.Sum(nil)) != 0 {
		return false, nil
	}

	// Verify merkle path.
	for currentLevel := len(t.mns) - 1; currentLevel > 0; currentLevel-- {
		currentIndex, currentDigest = parentIndex, parentDigest
		if currentIndex%2 == 0 {
			if currentIndex < len(t.mns[currentLevel])-1 {
				siblingDigest = t.mns[currentLevel][currentIndex+1]
			} else {
				siblingDigest = []byte{}
			}
			parentIndex = currentIndex / 2
			parentDigest = t.mns[currentLevel-1][parentIndex]
			first, second = currentDigest, siblingDigest
		} else {
			siblingDigest = t.mns[currentLevel][currentIndex-1]
			parentIndex = (currentIndex - 1) / 2
			parentDigest = t.mns[currentLevel-1][parentIndex]
			first, second = siblingDigest, currentDigest
		}
		h.Reset()
		h.Write(first)
		h.Write(second)
		if bytes.Compare(parentDigest, h.Sum(nil)) != 0 {
			return false, nil
		}
	}

	return true, nil
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
