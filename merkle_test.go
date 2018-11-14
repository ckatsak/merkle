package merkle

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"strings"
	"testing"
)

type Word string

func (w Word) Serialize() []byte {
	return []byte(w)
}

const (
	alpha   Word = "alpha"
	beta    Word = "beta"
	gamma   Word = "gamma"
	delta   Word = "delta"
	epsilon Word = "epsilon"
	zeta    Word = "zeta"
	eta     Word = "eta"
	theta   Word = "theta"
	yota    Word = "yota"
	kappa   Word = "kappa"
	lambda  Word = "lambda"
	mi      Word = "mi"
	ni      Word = "ni"
	ksi     Word = "ksi"
	omikron Word = "omikron"
	pi      Word = "pi"
	ro      Word = "ro"
	sigma   Word = "sigma"
	taph    Word = "taph"
	ipsilon Word = "ipsilon"
	phi     Word = "phi"
	chi     Word = "chi"
	psi     Word = "psi"
	omega   Word = "omega"

	kk Word = "kk"
)

var words = []Datum{
	alpha, beta, gamma, delta, epsilon, zeta, eta, theta, yota, kappa, lambda, mi, ni, ksi, omikron, pi, ro, sigma,
	taph, ipsilon, phi, chi, psi, omega,
}

func TestNewTree00(t *testing.T) {
	t.Log(calculateMerkleNumbers(24))

	tree, err := NewTree(crypto.SHA256,
		alpha, beta, gamma, delta, epsilon, zeta, eta, theta, yota, kappa, lambda,
		mi, ni, ksi, omikron, pi, ro, sigma, taph, ipsilon, phi, chi, psi, omega,
	)
	if err != nil {
		panic(err)
	}
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	for i := 0; i < tree.Height()-1; i++ {
		for j := 0; j < len(tree.mns[i]); j++ {
			t.Logf("(i=%2d,j=%2d)%s%x", i, j, strings.Repeat(" ", (i+1)*4), tree.mns[i][j])
		}
	}
	for i := 0; i < len(tree.tls); i++ {
		t.Logf("%x (\"%s\")", tree.tls[i].digest, tree.tls[i].datum)
	}
}

func TestVerify00(t *testing.T) {
	tree, err := NewTree(crypto.SHA256, words...)
	if err != nil {
		panic(err)
	}
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	var v bool
	for _, word := range words {
		t.Logf("Verifying \"%s\"...", word)
		if v, err = tree.VerifyDatum(word); err != nil {
			t.Logf("ERROR while verifying \"%s\": (%v, %v)", word, v, err)
		}
		t.Logf("\t\t\t%v", v)
	}
	t.Logf("Verifying \"%s\"...", kk)
	if v, err = tree.VerifyDatum(kk); err == nil {
		t.Fatalf("ERROR while verifying \"%s\": (%v, %v)", kk, v, err)
	}
	t.Logf("\t\t\t%v", v)
}

func TestLeaves00(t *testing.T) {
	tree, err := NewTree(crypto.SHA256, words...)
	if err != nil {
		panic(err)
	}
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	for i, serializedDatum := range tree.Leaves() {
		t.Logf("%2d. %s", i, serializedDatum)
	}
}
