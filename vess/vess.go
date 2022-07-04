// Bilinear Verifiably-Encrypted Signature Scheme on the BLS12-381 curve
//
// Originally proposed in https://crypto.stanford.edu/~dabo/pubs/papers/aggreg.pdf
// the scheme assumes a curve where an isomorphism between G2 and G1 exists
// (Type 2 pairing)
// This code adapts the original scheme to the BLS12-381 curve (Type 3 pairing)
// using the procedure detailed in https://eprint.iacr.org/2009/480.pdf

package vess

import (
	"fmt"
	"math/big"

	// TODO: remove dependency on gnark. Herumi's bls is enough
	gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/herumi/bls-eth-go-binary/bls"
)

type VESS struct {
	g1 gnark.G1Affine
	g2 gnark.G2Affine
}

func New() (*VESS, error) {
	if err := bls.Init(bls.BLS12_381); err != nil {
		return nil, err
	}
	if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
		return nil, err
	}
	bls.VerifyPublicKeyOrder(true)
	bls.VerifySignatureOrder(true)

	// Fetch G1 and G2 generators (affine coordinates)
	_, _, g1, g2 = gnark.Generators()

	return &VESS{g1: g1, g2: g2}, nil
}

func (v *VESS) Sign() {}

func (v *VESS) Verify() {}

func (v *VESS) Adjudicate() {}

func Test() {
	// Alice's keys
	// Secret (private) key
	aSKey := fr.Element{}
	aSKey.SetRandom()
	// Public key
	aPKey := gnark.G1Affine{}
	x := big.Int{}
	aPKey.ScalarMultiplication(&g1, aSKey.ToBigInt(&x))

	fmt.Printf("Alice's pubkey (G1): %x\n", aPKey.Marshal())

	// Adjudicator's keys
	// Secret (private) key
	adjSKey := fr.Element{}
	adjSKey.SetRandom()
	adjSKeyInt := big.Int{}
	adjSKey.ToBigIntRegular(&adjSKeyInt)
	adjPKeyG1 := gnark.G1Affine{}
	// Regular public key on G1
	adjPKeyG1.ScalarMultiplication(&g1, &adjSKeyInt)
	// Public key on G2. Required for Type 3 pairings
	adjPKeyG2 := gnark.G2Affine{}
	adjPKeyG2.ScalarMultiplication(&g2, &adjSKeyInt)

	fmt.Printf("Adjudicator pubkey (G1): %x\nAdjudicator pubkey (G2): %x\n",
		adjPKeyG1.Marshal(), adjPKeyG2.Marshal())

	// Compute h = H(M), sigma = h^x
	// Just do a regular BLS signature with Alice's key (on G1)
	// Use Herumi's library to make sure the signature is properly formatted
	msg := "Hello, World"
	ask := bls.SecretKey{}
	ask.SetDecString(x.String())
	asig := ask.Sign(msg)
	sigma := gnark.G2Affine{}
	sigma.Unmarshal(asig.SerializeUncompressed())
	fmt.Printf("Message: %s\nOriginal signature: %x\n", msg, sigma.Marshal())

	// Select r at random from Zp
	rel := fr.Element{}
	rel.SetRandom()
	r := big.Int{}
	rel.ToBigInt(&r)

	// Set mu = phi(g2)^r
	// Note the ETH2 spec swaps the G1 and G2 groups to get smaller public keys
	// Also note that phi(g2) == g1
	mu := gnark.G2Affine{}
	mu.ScalarMultiplication(&g2, &r)

	// Set sigma_2 = phi(v')^r
	// Reminder: phi(v') is is the adjudicator pubkey on G2
	sigma_2 := gnark.G2Affine{}
	sigma_2.ScalarMultiplication(&adjPKeyG2, &r)

	// Aggregate sigma and sigma_2 as omega = sigma * sigma_2
	// In the original paper, G1 is a multiplicative group. Here G1 is additive
	omega := gnark.G2Affine{}
	omega.Add(&sigma, &sigma_2)

	fmt.Printf("VESig: (%x, %x)\n", omega.Marshal(), mu.Marshal())
	origOmega := bls.G2{}
	origOmega.DeserializeUncompressed(omega.Marshal())
	origMu := bls.G2{}
	origMu.DeserializeUncompressed(mu.Marshal())

	// Verify
	// TODO: there are probably more efficient ways to do this check.
	// Look into how BLS libs do it internally.
	// Give a public key v, a message M, an a adjudicator's public key v', and
	// a verifiably encrypted signature (omega, mu); accept if
	// e(omega, g2) == e(h, v) . e(mu, v')
	// Friendly reminder that ETH2 swaps G1 and G2

	// e(omega, g2)
	pair0, _ := gnark.Pair([]gnark.G1Affine{g1}, []gnark.G2Affine{omega})

	// h = H(M)
	h0 := bls.HashAndMapToSignature([]byte(msg))
	h := gnark.G2Affine{}
	h.Unmarshal(h0.SerializeUncompressed())

	// e(h, v)
	pair1, _ := gnark.Pair([]gnark.G1Affine{aPKey}, []gnark.G2Affine{h})

	// e(mu, v')
	pair2, _ := gnark.Pair([]gnark.G1Affine{adjPKeyG1}, []gnark.G2Affine{mu})

	// e(h, v) * e(mu, v')
	pair1.Mul(&pair1, &pair2)

	// e(omega, g2) == e(h, v) . e(mu, v') ?
	if pair0 != pair1 {
		panic("Invalid signature")
	}

	// Adjudicate
	// sigma = omega / mu^adjSKey
	mu.ScalarMultiplication(&mu, &adjSKeyInt)
	omega.Sub(&omega, &mu)
	fmt.Printf("Recovered signature: %x\n", omega.Marshal())

	// TODO: and this one
	if sigma != omega {
		panic("Recovered signature does not match original signature")
	}
	fmt.Println("Recovered signature matches!")

	// Try do recover the original signature, but with threshold signatures (n-of-m scheme)
	minShares := 3
	totalShares := 10

	// Create a polynomial for the "threshold adjudicator" private key with degree n-1
	// This will require n shares out of m to reconstruct the key (n-of-m)
	adjKeyPoly := make([]bls.Fr, minShares)
	adjsk := bls.Fr{}
	adjsk.Deserialize(adjSKey.Marshal())

	// The free coefficient is the original private key
	adjKeyPoly[0] = adjsk

	// Random secret key coefficients
	for i := 1; i < minShares; i++ {
		fr := bls.Fr{}
		fr.SetByCSPRNG()
		adjKeyPoly[i] = fr
	}

	// Evaluate the polynomial at m points (the key shares)
	// Note that we're creating the shares from a single private key
	// In a real setting, a DKG protocol would probably be used
	shares := make([]bls.Fr, totalShares)
	for i := 0; i < len(shares); i++ {
		x := bls.Fr{}
		x.SetInt64(int64(i + 1))
		y := bls.Fr{}
		bls.FrEvaluatePolynomial(&y, adjKeyPoly, &x)
		shares[i] = y
	}

	// At this point, each member would already have its key share

	// Try to calculate mu^adjKey, using n shares
	// We're just using the first n, but it can be any n valid shares
	mub := bls.G2{}
	mub.Deserialize(origMu.Serialize())
	res := make([]bls.G2, minShares)
	for i := 0; i < len(res); i++ {
		bls.G2Mul(&res[i], &mub, &shares[i])
	}

	// Lagrange interpolation with n points to recover mu^adjKey
	xs := make([]bls.Fr, minShares)
	for i := 0; i < len(xs); i++ {
		xs[i] = bls.Fr{}
		xs[i].SetInt64(int64(i + 1))
	}
	err := bls.G2LagrangeInterpolation(&mub, xs, res)
	if err != nil {
		panic(err)
	}

	// Final adjudication step
	omegab := bls.G2{}
	omegab.DeserializeUncompressed(origOmega.SerializeUncompressed())
	bls.G2Sub(&omegab, &omegab, &mub)
	fmt.Printf("Recovered signature (n-of-m): %x\n", omegab.SerializeUncompressed())
}
