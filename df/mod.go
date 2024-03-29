package df

// Package df implements trapdoor delay functions.
//
// Verifiability is not needed and so left out.

import (
	"io"
	"math/big"
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// an RSA group serving as public parameters for a delay function.
type RsaGroup struct {
	Mod *big.Int
}

// RSAGroup with its trapdoor parameter.
type RsaGroupWithTrapdoor struct {
	RsaGroup
	Order *big.Int
}

const bits = 4096

// Generate a random RSAGroup
func NewRsaGroup(randomnessSource io.Reader) (*RsaGroupWithTrapdoor, error) {
	p, err := rand.Prime(randomnessSource, bits/2)
	if err != nil {
		return nil, err
	}
	// TODO: make sure p != q, can happen with small size fuzzing
	// TODO: whatever standard RSA parameter safety checks exist
	q, err := rand.Prime(randomnessSource, bits/2)
	if err != nil {
		return nil, err
	}
	mod := new(big.Int).Mul(p, q)
	one := new(big.Int).SetUint64(1)
	p.Sub(p, one)
	q.Sub(q, one)
	order := new(big.Int).Mul(p, q)
	return &RsaGroupWithTrapdoor{RsaGroup{mod}, order}, nil
}

type Element *big.Int

var two = new(big.Int).SetUint64(2)
// Perform exponentiation using the trapdoor.
func (params *RsaGroupWithTrapdoor) FastEval(input Element, iterations uint64) Element {
	x := new(big.Int).SetUint64(iterations)
	x.Exp(two, x, params.Order)
	x.Exp(input, x, params.Mod)
	return x
}

// Perform exponentiation slowly.
func (params *RsaGroup) Eval(input Element, iterations uint64) Element {
	x := new(big.Int).Set(input)
	x.Mod(x, params.Mod)
	for ; iterations > 0; iterations-- {
		x.Mul(x, x)
		x.Mod(x, params.Mod)
	}
	return x
}

// Hash data to a pseudorandom group element.
func (params *RsaGroup) HashToGroup(data []byte) Element {
	h := sha3.NewCShake256([]byte("dsw"), []byte("hashToGroup"))
	h.Write(data)
	out := make([]byte, bits/8 + 32)
	h.Read(out)
	x := new(big.Int).SetBytes(out)
	x.Mod(x, params.Mod)
	// hope x is not 0 or ±1
	return x
}
