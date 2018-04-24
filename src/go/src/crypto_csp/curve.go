package crypto_csp

import (
	"errors"
	"math/big"
)

var (
	zero    *big.Int = big.NewInt(0)
	bigInt1 *big.Int = big.NewInt(1)
	bigInt2 *big.Int = big.NewInt(2)
	bigInt3 *big.Int = big.NewInt(3)
)

type Curve struct {
	P  *big.Int
	Q  *big.Int
	A  *big.Int
	B  *big.Int

	// Basic point X and Y coordinates
	Bx *big.Int
	By *big.Int

	// Byte mode of a curve
	ByteSize int
	BitSize int

	// Temporary variable for the add method
	t  *big.Int
	tx *big.Int
	ty *big.Int
}

func NewCurve(p, q, a, b, bx, by []byte) (*Curve, error) {
	c := Curve{
		P:  bytes2big(p[:]),
		Q:  bytes2big(q[:]),
		A:  bytes2big(a[:]),
		B:  bytes2big(b[:]),
		Bx: bytes2big(bx[:]),
		By: bytes2big(by[:]),
		ByteSize: 32,
		BitSize: 256,
		t:  big.NewInt(0),
		tx: big.NewInt(0),
		ty: big.NewInt(0),
	}

	r1 := big.NewInt(0)
	r2 := big.NewInt(0)
	r1.Mul(c.By, c.By)
	r1.Mod(r1, c.P)
	r2.Mul(c.Bx, c.Bx)
	r2.Add(r2, c.A)
	r2.Mul(r2, c.Bx)
	r2.Add(r2, c.B)
	r2.Mod(r2, c.P)
	if r2.Cmp(big.NewInt(0)) == -1 {
		r2.Add(r2, c.P)
	}
	if r1.Cmp(r2) != 0 {
		return nil, errors.New("Invalid curve parameters")
	}
	return &c, nil
}

func (c *Curve) pos(v *big.Int) {
	if v.Cmp(zero) < 0 {
		v.Add(v, c.P)
	}
}

func (c *Curve) Add(p1x, p1y, p2x, p2y *big.Int) (*big.Int, *big.Int) {
	if p1x.Cmp(p2x) == 0 && p1y.Cmp(p2y) == 0 {
		// double
		c.t.Mul(p1x, p1x)
		c.t.Mul(c.t, bigInt3)
		c.t.Add(c.t, c.A)
		c.tx.Mul(bigInt2, p1y)
		c.tx.ModInverse(c.tx, c.P)
		c.t.Mul(c.t, c.tx)
		c.t.Mod(c.t, c.P)
	} else {
		c.tx.Sub(p2x, p1x)
		c.tx.Mod(c.tx, c.P)
		c.pos(c.tx)
		c.ty.Sub(p2y, p1y)
		c.ty.Mod(c.ty, c.P)
		c.pos(c.ty)
		c.t.ModInverse(c.tx, c.P)
		c.t.Mul(c.t, c.ty)
		c.t.Mod(c.t, c.P)
	}
	c.tx.Mul(c.t, c.t)
	c.tx.Sub(c.tx, p1x)
	c.tx.Sub(c.tx, p2x)
	c.tx.Mod(c.tx, c.P)
	c.pos(c.tx)
	c.ty.Sub(p1x, c.tx)
	c.ty.Mul(c.ty, c.t)
	c.ty.Sub(c.ty, p1y)
	c.ty.Mod(c.ty, c.P)
	c.pos(c.ty)
	p1x.Set(c.tx)
	p1y.Set(c.ty)
	return c.tx, c.ty
}

func (c *Curve) exp(degree, xS, yS *big.Int) (*big.Int, *big.Int, error) {
	if degree.Cmp(zero) == 0 {
		return nil, nil, errors.New("Bad degree value")
	}
	dg := big.NewInt(0).Sub(degree, bigInt1)
	tempX := big.NewInt(0).Set(xS)
	tempY := big.NewInt(0).Set(yS)
	cx := big.NewInt(0).Set(xS)
	cy := big.NewInt(0).Set(yS)
	for dg.Cmp(zero) != 0 {
		if dg.Bit(0) == 1 {
			c.Add(tempX, tempY, cx, cy)
		}
		dg.Rsh(dg, 1)
		c.Add(cx, cy, cx, cy)
	}
	if !c.IsOnCurve(tempX, tempY) {
		return big.NewInt(0), big.NewInt(0), nil
	}
	return tempX, tempY, nil
}

func (curve *Curve) IsOnCurve(x, y *big.Int) bool {
	// y² = x³ + ax + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(x, curve.A)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3.Cmp(y2) == 0
}

// DecompressPoint decompresses a point on the given curve given the X point and
// the solution to use.
func (curve *Curve) DecompressPoint(x *big.Int, ybit bool) (*big.Int, error) {
	// y = +-sqrt(x^3 + ax + b)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	aX := new(big.Int).Mul(x, curve.A)
	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	y := x3.ModSqrt(x3, curve.P)
	if y == nil {
		return nil, errors.New("Failed to decompress elliptic curve point from given X coordinate")
	}

	if ybit != isOdd(y) {
		y.Sub(curve.P, y)
	}
	if ybit != isOdd(y) {
		return nil, errors.New("ybit doesn't match oddness")
	}
	return y, nil
}

func (curve *Curve) ScalarMult(Bx, By *big.Int, k []byte) (*big.Int, *big.Int, error) {
	dg := big.NewInt(0).Set(bytes2big(k))
	if dg.Cmp(bigInt1) == 0 {
		return Bx, By, nil
	} else {
		return curve.exp(dg, Bx, By)
	}
}

func (curve *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int, error) {
	dg := big.NewInt(0).Set(bytes2big(k))
	if dg.Cmp(bigInt1) == 0 {
		return curve.Bx, curve.By, nil
	} else {
		return curve.exp(dg, curve.Bx, curve.By)
	}
}