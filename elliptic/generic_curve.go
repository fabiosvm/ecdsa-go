package elliptic

import (
	"errors"
	"io"
	"math/big"
)

type GenericCurve struct {
	KeySize    int
	A, B, P, N *big.Int
	G          *Point
}

var (
	Secp256r1 = newSecp256r1()
)

func newSecp256r1() *GenericCurve {
	a, _ := new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16)
	b, _ := new(big.Int).SetString("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
	p, _ := new(big.Int).SetString("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
	n, _ := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	x, _ := new(big.Int).SetString("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
	y, _ := new(big.Int).SetString("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
	g := NewPoint(x, y)
	return &GenericCurve{
		KeySize: 32,
		A:       a,
		B:       b,
		P:       p,
		N:       n,
		G:       g,
	}
}

func (c *GenericCurve) GenerateValidScalar(rand io.Reader) (*big.Int, error) {
	bytes := make([]byte, c.KeySize)
	var scalar *big.Int
	for {
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, err
		}
		scalar = new(big.Int).SetBytes(bytes)
		if c.IsValidScalar(scalar) {
			break
		}
	}
	return scalar, nil
}

func (c *GenericCurve) IsValidScalar(scalar *big.Int) bool {
	return scalar.Sign() > 0 && scalar.Cmp(c.N) < 0
}

func (c *GenericCurve) ContainsPoint(p *Point) bool {
	// l = mod(p.Y ** 2, c.P)
	l := new(big.Int).Set(p.Y)
	l = l.Mul(l, p.Y)
	l = l.Mod(l, c.P)
	// r = mod(p.X ** 3 + c.A * p.X + c.B, c.P)
	t0 := new(big.Int).Set(p.X)
	t0 = t0.Mul(t0, p.X)
	t0 = t0.Mul(t0, p.X)
	t1 := new(big.Int).Set(c.A)
	t1 = t1.Mul(t1, p.X)
	r := t0.Add(t0, t1)
	r = r.Add(r, c.B)
	r = r.Mod(r, c.P)
	// l = r ?
	return l.Cmp(r) == 0
}

func (c *GenericCurve) AddPoints(p, q *Point) (*Point, error) {
	if p.IsAtInfinity() {
		return q, nil
	}
	if q.IsAtInfinity() {
		return p, nil
	}
	if (p.X.Cmp(q.X) == 0) && (p.Y.Cmp(new(big.Int).Neg(q.Y))) == 0 {
		inf := NewPointAtInfinity()
		return inf, nil
	}
	// lambda = mod((q.Y − p.Y) * modInv(q.X​ − p.X, c.P), c.P)
	n := new(big.Int).Set(q.Y)
	n = n.Sub(n, p.Y)
	d := new(big.Int).Set(q.X)
	d = d.Sub(d, p.X)
	d = new(big.Int).ModInverse(d, c.P)
	if d == nil {
		return nil, errors.New("Cannot inverse denominator")
	}
	lambda := n.Mul(n, d)
	lambda = lambda.Mod(lambda, c.P)
	// rX = mod(lamda ** 2 − p.X − q.X, c.P)
	rX := new(big.Int).Set(lambda)
	rX = rX.Mul(rX, lambda)
	rX = rX.Sub(rX, p.X)
	rX = rX.Sub(rX, q.X)
	rX = rX.Mod(rX, c.P)
	// rY = mod(lamda * (p.X − rX) − p.Y, c.P)
	rY := new(big.Int).Set(p.X)
	rY = rY.Sub(rY, rX)
	rY = rY.Mul(rY, lambda)
	rY = rY.Sub(rY, p.Y)
	rY = rY.Mod(rY, c.P)
	return NewPoint(rX, rY), nil
}

func (c *GenericCurve) DoublePoint(p *Point) (*Point, error) {
	if p.IsAtInfinity() || p.Y.Cmp(big.NewInt(0)) == 0 {
		return NewPointAtInfinity(), nil
	}
	// lambda = mod((3 *p.X ** 2 + c.A) * modinv(2 * p.Y, c.P), c.P)
	n := new(big.Int).Set(p.X)
	n = n.Mul(n, p.X)
	n = n.Mul(n, big.NewInt(3))
	n = n.Add(n, c.A)
	d := new(big.Int).Set(p.Y)
	d = d.Mul(d, big.NewInt(2))
	d = d.ModInverse(d, c.P)
	if d == nil {
		return nil, errors.New("Cannot inverse denominator")
	}
	lambda := n.Mul(n, d)
	lambda = lambda.Mod(lambda, c.P)
	// rX = mod(lamda ** 2 − 2 * p.X, c.P)
	t0 := new(big.Int).Set(lambda)
	t0 = t0.Mul(t0, lambda)
	t1 := new(big.Int).Set(p.X)
	t1 = t1.Mul(t1, big.NewInt(2))
	rX := t0.Sub(t0, t1)
	rX = rX.Mod(rX, c.P)
	// rY = mod(lambda * (p.X − rX) − p.Y), c.P)
	t0 = new(big.Int).Set(p.X)
	t0 = t0.Sub(t0, rX)
	rY := t0.Mul(t0, lambda)
	rY = rY.Sub(rY, p.Y)
	rY = rY.Mod(rY, c.P)
	return NewPoint(rX, rY), nil
}

func (c *GenericCurve) ScalarMultiplyPoint(p *Point, scalar *big.Int) (*Point, error) {
	r := NewPointAtInfinity()
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		var err error
		r, err = c.DoublePoint(r)
		if err != nil {
			return nil, err
		}
		if scalar.Bit(i) == 1 {
			r, err = c.AddPoints(r, p)
			if err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func (c *GenericCurve) ScalarBaseMultiplyPoint(scalar *big.Int) (*Point, error) {
	return c.ScalarMultiplyPoint(c.G, scalar)
}