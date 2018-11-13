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
)

func TestNewTree00(t *testing.T) {
	t.Log(calculateMerkleNumbers(24))

	tree, err := NewTree(crypto.SHA256,
		alpha, beta, gamma, delta, epsilon, zeta, eta, theta, yota, kappa, lambda,
		mi, ni, ksi, omikron, pi, ro, sigma, taph, ipsilon, phi, chi, psi, omega,
	)
	if err != nil {
		panic(err)
	}
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	for i := 0; i < tree.Height(); i++ {
		for j := 0; j < len(tree.mns[i]); j++ {
			t.Logf("(i=%2d,j=%2d)%s%x", i, j, strings.Repeat(" ", (i+1)*4), tree.mns[i][j])
		}
	}
	for i := 0; i < len(tree.tls); i++ {
		t.Logf("%x (\"%s\")", tree.tls[i].digest, tree.tls[i].datum)
	}
}
