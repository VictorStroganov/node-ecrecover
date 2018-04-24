package crypto_csp

import (
	"errors"
	"math/big"
)

type PublicKey struct {
	Curve *Curve
	Ds    int
	X     *big.Int
	Y     *big.Int
}

func NewPublicKey(curve *Curve, raw []byte) (*PublicKey, error) {
	if len(raw) != 2*curve.ByteSize {
		return nil, errors.New("Invalid public key length")
	}
	key := make([]byte, 2*curve.ByteSize)
	copy(key, raw)
	reverse(key)
	return &PublicKey{
		curve,
		curve.ByteSize,
		bytes2big(key[curve.ByteSize : 2*curve.ByteSize]),
		bytes2big(key[:curve.ByteSize]),
	}, nil
}

func (pk *PublicKey) Raw() []byte {
	raw := append(pad(pk.Y.Bytes(), pk.Ds), pad(pk.X.Bytes(), pk.Ds)...)
	reverse(raw)
	return raw
}

func (pk *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	if len(signature) != 2*pk.Ds {
		return false, errors.New("Invalid signature length")
	}
	s := bytes2big(signature[:pk.Ds])
	r := bytes2big(signature[pk.Ds:])
	if r.Cmp(zero) <= 0 || r.Cmp(pk.Curve.Q) >= 0 || s.Cmp(zero) <= 0 || s.Cmp(pk.Curve.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pk.Curve.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}

	v := big.NewInt(0)
	v.ModInverse(e, pk.Curve.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pk.Curve.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pk.Curve.Q)
	z2.Sub(pk.Curve.Q, z2)
	p1x, p1y, err := pk.Curve.exp(z1, pk.Curve.Bx, pk.Curve.By)
	if err != nil {
		return false, err
	}
	q1x, q1y, err := pk.Curve.exp(z2, pk.X, pk.Y)
	if err != nil {
		return false, err
	}
	lm := big.NewInt(0)
	lm.Sub(q1x, p1x)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pk.Curve.P)
	}
	lm.ModInverse(lm, pk.Curve.P)
	z1.Sub(q1y, p1y)
	lm.Mul(lm, z1)
	lm.Mod(lm, pk.Curve.P)
	lm.Mul(lm, lm)
	lm.Mod(lm, pk.Curve.P)
	lm.Sub(lm, p1x)
	lm.Sub(lm, q1x)
	lm.Mod(lm, pk.Curve.P)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pk.Curve.P)
	}
	lm.Mod(lm, pk.Curve.Q)
	return lm.Cmp(r) == 0, nil
}