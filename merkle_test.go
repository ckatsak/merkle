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
	alpha, beta, gamma, delta, epsilon    Word = "alpha", "beta", "gamma", "delta", "epsilon"
	zeta, eta, theta, yota, kappa, lambda Word = "zeta", "eta", "theta", "yota", "kappa", "lambda"
	mi, ni, ksi, omikron, pi, ro, sigma   Word = "mi", "ni", "ksi", "omikron", "pi", "ro", "sigma"
	taph, ipsilon, phi, chi, psi, omega   Word = "taph", "ipsilon", "phi", "chi", "psi", "omega"

	A, B, C, D, E, F, G, H, I, J, K, L, M Word = "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"
	N, O, P, Q, R, S, T, U, V, W, X, Y, Z Word = "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"

	kk Word = "kk"
)

var (
	grAlphabet = []Datum{
		alpha, beta, gamma, delta, epsilon, zeta, eta, theta, yota, kappa, lambda,
		mi, ni, ksi, omikron, pi, ro, sigma, taph, ipsilon, phi, chi, psi, omega,
	}

	enAlphabetCap = []Datum{A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z}
)

func TestNewTree00(t *testing.T) {
	if _, err := NewTree(crypto.SHA512, alpha); err != nil {
		t.Logf("got (%v), as expected", err)
	} else {
		t.Fatalf("want (%v); got %v", ErrHashUnavailable{}, err)
	}
}
func TestNewTree01(t *testing.T) {
	var nilData []Datum
	if _, err := NewTree(crypto.SHA256, nilData...); err != nil {
		t.Logf("got (%v), as expected", err)
	} else {
		t.Fatalf("want (%v); got %v", ErrNoData{}, err)
	}
}
func TestNewTree02(t *testing.T) {
	t.Log(calculateMerkleNumbers(24))

	tree, err := NewTree(crypto.SHA256,
		alpha, beta, gamma, delta, epsilon, zeta, eta, theta, yota, kappa, lambda,
		mi, ni, ksi, omikron, pi, ro, sigma, taph, ipsilon, phi, chi, psi, omega,
	)
	if err != nil {
		t.Fatal(err)
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
	tree, err := NewTree(crypto.SHA256, grAlphabet...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	var v bool
	for _, word := range grAlphabet {
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
	tree, err := NewTree(crypto.SHA256, grAlphabet...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	for i, serializedDatum := range tree.Leaves() {
		t.Logf("%2d. %s", i, serializedDatum)
	}

	// Print the tree.
	for i := 0; i < tree.Height()-1; i++ {
		for j := 0; j < len(tree.mns[i]); j++ {
			t.Logf("(i=%2d,j=%2d)%s%x", i, j, strings.Repeat(" ", (i+1)*4), tree.mns[i][j])
		}
	}
	for i := 0; i < len(tree.tls); i++ {
		t.Logf("%x (\"%s\")", tree.tls[i].digest, tree.tls[i].datum)
	}
}

func TestAppendReconstruct00(t *testing.T) {
	tree, err := NewTree(crypto.SHA256, grAlphabet...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BEFORE THE EXTENSION:")
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	var nilData []Datum = nil
	tree.AppendAndReconstruct(nilData...)

	t.Logf("")
	t.Logf("AFTER THE EXTENSION:")
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())
}
func TestAppendReconstruct01(t *testing.T) {
	tree, err := NewTree(crypto.SHA256, grAlphabet...)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("BEFORE THE EXTENSION:")
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	tree.AppendAndReconstruct(enAlphabetCap[:13]...)

	t.Logf("")
	t.Logf("AFTER THE EXTENSION:")
	t.Logf("tree.MerkleRoot(): %x", tree.MerkleRoot())
	t.Log("tree.Height():", tree.Height())
	t.Log("tree.Size():", tree.Size())
	t.Log("tree.MerkleSize():", tree.MerkleSize())
	t.Log("tree.NumLeaves():", tree.NumLeaves())

	// Print the tree.
	for i := 0; i < tree.Height()-1; i++ {
		for j := 0; j < len(tree.mns[i]); j++ {
			t.Logf("(i=%2d,j=%2d)%s%x", i, j, strings.Repeat(" ", (i+1)*4), tree.mns[i][j])
		}
	}
	for i := 0; i < len(tree.tls); i++ {
		t.Logf("%x (\"%s\")", tree.tls[i].digest, tree.tls[i].datum)
	}

	// Print the leaves.
	for i, serializedDatum := range tree.Leaves() {
		t.Logf("%2d. %s", i, serializedDatum)
	}

	// Verify stuff
	var v bool
	for _, word := range grAlphabet {
		t.Logf("Verifying \"%s\"...", word)
		if v, err = tree.VerifyDatum(word); err != nil {
			t.Logf("ERROR while verifying \"%s\": (%v, %v)", word, v, err)
		}
		t.Logf("\t\t\t%v", v)
	}
	for _, word := range enAlphabetCap {
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
