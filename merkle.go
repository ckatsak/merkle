// Copyright (c) 2018, Christos Katsakioris
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Package merkle implements a very simple, immutable, in-memory, generic,
// "hash function-agnostic" merkle tree.
package merkle

import (
	"bytes"
	"crypto"
	"hash"
	"sort"
)

// Datum is the interface that any piece of data has to implement so as to be
// able to be contained in the leaves of the merkle tree.
type Datum interface {
	// Serialize must return a serialized representation of the Datum.
	Serialize() []byte
}

type (
	// ErrHashUnavailable signifies that the requested hash function has
	// not been linked into the binary.
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

// NewTree creates a new merkle tree given one of the available (i.e. linked
// into the binary) hash functions and a bunch of data.
//
// It returns a non-nil error either if the requested hash function has not
// been linked into the binary, or if data are not given at all.
func NewTree(hash crypto.Hash, data ...Datum) (*Tree, error) {
	if !hash.Available() {
		return nil, ErrHashUnavailable{}
	}
	h := hash.New()

	if len(data) == 0 {
		return nil, ErrNoData{}
	}
	// Create the leaves...
	tls := appendTreeLeaves(h, nil, data)
	// ...and construct the merkle nodes above them.
	mns := constructMerkleNodes(h, tls)

	return &Tree{
		hash: hash,
		mns:  mns,
		tls:  tls,
	}, nil
}

// AppendAndReconstruct appends the given data as new tree leaves, and
// reconstructs the merkle tree to take them into account as well.
//
// This obviously modifies the merkle root of the tree.
func (t *Tree) AppendAndReconstruct(data ...Datum) {
	if len(data) == 0 {
		return
	}
	h := t.hash.New()
	// Append the new leaves...
	t.tls = appendTreeLeaves(h, t.tls, data)
	// ...and reconstruct the merkle nodes above them.
	t.mns = constructMerkleNodes(h, t.tls)
}

// DeleteAndReconstruct deletes the given data from the tree leaves, and
// reconstructs the merkle tree on the new (reduced) number of leaves.
//
// This obviously modifies the merkle root of the tree.
func (t *Tree) DeleteAndReconstruct(data ...Datum) {
	if len(data) == 0 {
		return
	}
	// Delete the appropriate leaves...
	t.tls = deleteTreeLeaves(t.tls, data)
	// ...and reconstruct the merkle nodes above the remaining ones.
	t.mns = constructMerkleNodes(t.hash.New(), t.tls)
}

// VerifyDigest verifies that the given (leaf) hash digest is present in the
// merkle tree, in which case it returns true and a nil error value.
//
// It requires O(L) search among the leaves and O(log2(L)) hash calculations.
//
// If the given hash digest cannot be verified, VerifyDigest returns false.
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

// Leaves returns a slice of all pieces of Data stored in the merkle tree (in
// their serialized format) in the order that they were inserted by the user.
func (t *Tree) Leaves() [][]byte {
	tls2 := make([]treeLeaf, len(t.tls))
	copy(tls2, t.tls)
	sort.Slice(tls2, func(i, j int) bool {
		return tls2[i].orderedID < tls2[j].orderedID
	})

	ret := make([][]byte, len(tls2))
	retSeq := make([]byte, 0)
	currentIndex := 0
	for i := range tls2 {
		retSeq = append(retSeq, tls2[i].datum...)
		ret[i] = retSeq[currentIndex : currentIndex+len(tls2[i].datum)]
		currentIndex += len(tls2[i].datum)
	}
	return ret
}

func appendTreeLeaves(h hash.Hash, oldTreeLeaves []treeLeaf, newData []Datum) (newTreeLeaves []treeLeaf) {
	newTreeLeaves = make([]treeLeaf, len(oldTreeLeaves), len(oldTreeLeaves)+len(newData))
	copy(newTreeLeaves, oldTreeLeaves)
	for i := range newData {
		serializedDatum := newData[i].Serialize()
		h.Reset()
		h.Write(serializedDatum)
		newTreeLeaves = append(newTreeLeaves, treeLeaf{
			digest:    h.Sum(nil),
			datum:     serializedDatum,
			orderedID: uint(len(oldTreeLeaves) + i),
		})
	}
	sort.Slice(newTreeLeaves, func(i, j int) bool {
		return bytes.Compare(newTreeLeaves[i].datum, newTreeLeaves[j].datum) == -1
	})
	return
}

func deleteTreeLeaves(oldTreeLeaves []treeLeaf, delData []Datum) (newTreeLeaves []treeLeaf) {
	// Serialize all data to be deleted.
	delSerializedData := make([][]byte, 0, len(delData))
	for i := range delData {
		delSerializedData = append(delSerializedData, delData[i].Serialize())
	}
	// Create a copy of oldTreeLeaves to process it.
	oldTls := make([]treeLeaf, len(oldTreeLeaves))
	copy(oldTls, oldTreeLeaves)
	// Find each of the serializedData to be deleted and remove them from the copy.
	for i := range delSerializedData {
		j := sort.Search(len(oldTls), func(k int) bool {
			return bytes.Compare(oldTls[k].datum, delSerializedData[i]) >= 0
		})
		if j < len(oldTls) && bytes.Compare(oldTls[j].datum, delSerializedData[i]) == 0 {
			oldTls = append(oldTls[:j], oldTls[j+1:]...)
		}
	}
	// Sort oldTls by orderedID, and reset the orderedIDs.
	sort.Slice(oldTls, func(i, j int) bool {
		return oldTls[i].orderedID < oldTls[j].orderedID
	})
	for i := range oldTls {
		oldTls[i].orderedID = uint(i)
	}
	// Copy oldTls to a new slice to avoid wasting capacity.
	newTreeLeaves = make([]treeLeaf, len(oldTreeLeaves)-len(delData))
	copy(newTreeLeaves, oldTls)
	// Finally, sort newTreeLeaves by serializedDatum again.
	sort.Slice(newTreeLeaves, func(i, j int) bool {
		return bytes.Compare(newTreeLeaves[i].datum, newTreeLeaves[j].datum) == -1
	})
	return
}

// mns[0][0] --> ROOT
// mns[1][0] mns[1][1]
// mns[2][0] mns[2][1] mns[2][2] mns[2][3]
// mns[3][0] mns[3][1] mns[3][2] mns[3][3] mns[3][4] mns[3][5] mns[3][6] mns[3][7]
//  . . .
func constructMerkleNodes(h hash.Hash, tls []treeLeaf) (mns [][][]byte) {
	numMerkleNodes, rowSizes := calculateMerkleNumbers(len(tls))
	mnsSeq := make([]byte, 0, h.Size()*numMerkleNodes)
	mns = make([][][]byte, len(rowSizes))
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
	return
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
