package ecdsa

import (
	"errors"
	"io"
	"math/big"

	elliptic "github.com/fabiosvm/ecdsa-go/elliptic"
)

type ECDSA struct {
	Curve *elliptic.Curve
}

func NewECDSA(curve *elliptic.Curve) *ECDSA {
	return &ECDSA{
		Curve: curve,
	}
}

func (e *ECDSA) PrivateKeyIsValid(privKey *PrivateKey) bool {
	return e.Curve.IsValidScalar(privKey.D)
}

func (e *ECDSA) PublicKeyIsValid(pubKey *PublicKey) bool {
	if pubKey.P.IsAtInfinity() {
		return false
	}
	if pubKey.P.X.Cmp(big.NewInt(0)) < 0 || pubKey.P.X.Cmp(e.Curve.P) >= 0 ||
		pubKey.P.Y.Cmp(big.NewInt(0)) < 0 || pubKey.P.Y.Cmp(e.Curve.P) >= 0 {
		return false
	}
	if !e.Curve.IsOnCurve(pubKey.P) {
		return false
	}
	// TODO: Complete this method.
	return true
}

func (e *ECDSA) GeneratePrivateKey(rand io.Reader) (*PrivateKey, error) {
	d, err := e.Curve.GenerateValidScalar(rand)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(d), nil
}

func (e *ECDSA) PublicKey(privKey *PrivateKey) (*PublicKey, error) {
	if !e.PrivateKeyIsValid(privKey) {
		return nil, errors.New("Invalid private key")
	}
	p := e.Curve.ScalarBaseMultiplyPoint(privKey.D)
	return NewPublicKey(p), nil
}

func (e *ECDSA) CompressPublicKey(pubKey *PublicKey) ([]byte, error) {
	if !e.PublicKeyIsValid(pubKey) {
		return nil, errors.New("Invalid public key")
	}
	b := byte(0x02)
	if pubKey.P.Y.Bit(0) == 1 {
		b = 0x03
	}
	compressed := make([]byte, e.Curve.KeySize+1)
	compressed[0] = b
	xBytes := pubKey.P.X.Bytes()
	copy(compressed[1:], xBytes)
	return compressed, nil
}

func (e *ECDSA) DecompressPublicKey(bytes []byte) (*PublicKey, error) {
	if len(bytes) != e.Curve.KeySize+1 {
		return nil, errors.New("Invalid compressed public key")
	}
	xBytes := make([]byte, e.Curve.KeySize)
	copy(xBytes, bytes[1:])
	x := new(big.Int).SetBytes(xBytes)
	b := bytes[0]
	y, n := e.Curve.ComputeY(x)
	if b == 0x03 {
		y = n
	}
	p := elliptic.NewPoint(x, y)
	return NewPublicKey(p), nil
}

func (e *ECDSA) Sign(hash []byte, privKey *PrivateKey, rand io.Reader) (*Signature, error) {
	var r, s *big.Int
	for {
		k, err := e.Curve.GenerateValidScalar(rand)
		if err != nil {
			return nil, err
		}
		p := e.Curve.ScalarBaseMultiplyPoint(k)
		// r = mod(p.X, c.N)
		r = new(big.Int).Set(p.X)
		r = r.Mod(r, e.Curve.N)
		if r.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		// s = mod(modInv(k, c.N) * (hash + r * privKey.D), c.N)
		t0 := new(big.Int).SetBytes(hash)
		t1 := new(big.Int).ModInverse(k, e.Curve.N)
		if t1 == nil {
			panic("ModInverse failed")
		}
		t2 := new(big.Int).Set(privKey.D)
		t2 = t2.Mul(t2, r)
		t2 = t2.Add(t2, t0)
		s = new(big.Int).Mul(t1, t2)
		s = s.Mod(s, e.Curve.N)
		if s.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		break
	}
	return NewSignature(r, s), nil
}

func (e *ECDSA) VerifySignature(hash []byte, sig *Signature, pubKey *PublicKey) bool {
	r, s := sig.R, sig.S
	if !e.Curve.IsValidScalar(r) || !e.Curve.IsValidScalar(s) {
		return false
	}
	// w = modInv(s, c.N)
	w := new(big.Int).Set(s)
	w = w.ModInverse(w, e.Curve.N)
	if w == nil {
		panic("ModInverse failed")
	}
	// u1 = mod(hash * w, c.N)
	u1 := new(big.Int).SetBytes(hash)
	u1 = u1.Mul(u1, w)
	u1 = u1.Mod(u1, e.Curve.N)
	// u2 = mod(r * w, c.N)
	u2 := new(big.Int).Set(r)
	u2 = u2.Mul(u2, w)
	u2 = u2.Mod(u2, e.Curve.N)
	// p = u1 * G + u2 * Q
	t0 := e.Curve.ScalarBaseMultiplyPoint(u1)
	t1 := e.Curve.ScalarMultiplyPoint(pubKey.P, u2)
	p := e.Curve.AddPoints(t0, t1)
	// r = mod(p.X, c.N) ?
	pX := new(big.Int).Set(p.X)
	pX = pX.Mod(pX, e.Curve.N)
	return r.Cmp(pX) == 0
}
