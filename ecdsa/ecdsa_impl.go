package ecdsa

import (
	"errors"
	"io"
	"math/big"

	elliptic "github.com/fabiosvm/ecdsa-go/elliptic"
)

type ECDSAImpl struct {
	Curve *elliptic.GenericCurve
}

func NewECDSA(curve *elliptic.GenericCurve) *ECDSAImpl {
	return &ECDSAImpl{
		Curve: curve,
	}
}

func (e *ECDSAImpl) PrivateKeyIsValid(privKey *PrivateKey) bool {
	return e.Curve.IsValidScalar(privKey.D)
}

func (e *ECDSAImpl) PublicKeyIsValid(pubKey *PublicKey) bool {
	// TODO: Complete this method.
	return e.Curve.ContainsPoint(pubKey.P)
}

func (e *ECDSAImpl) GeneratePrivateKey(rand io.Reader) (*PrivateKey, error) {
	d, err := e.Curve.GenerateValidScalar(rand)
	if err != nil {
		return nil, err
	}
	return NewPrivateKey(d), nil
}

func (e *ECDSAImpl) PublicKey(privKey *PrivateKey) (*PublicKey, error) {
	if !e.PrivateKeyIsValid(privKey) {
		return nil, errors.New("Invalid private key")
	}
	p, err := e.Curve.ScalarBaseMultiplyPoint(privKey.D)
	if err != nil {
		return nil, err
	}
	return NewPublicKey(p), nil
}

func (e *ECDSAImpl) Sign(hash []byte, privKey *PrivateKey, rand io.Reader) (*Signature, error) {
	var r, s *big.Int
	for {
		k, err := e.Curve.GenerateValidScalar(rand)
		if err != nil {
			return nil, err
		}
		p, err := e.Curve.ScalarBaseMultiplyPoint(k)
		if err != nil {
			return nil, err
		}
		// r = mod(p.X, c.N)
		r = new(big.Int).Set(p.X)
		r = r.Mod(r, e.Curve.N)
		if r.Cmp(big.NewInt(0)) == 0 {
			continue
		}
		// s = mod(modInv(k, c.N) * (hash + r * privKey.D), c.N)
		t0 := new(big.Int).SetBytes(hash)
		t1 := new(big.Int).ModInverse(k, e.Curve.N)
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

func (e *ECDSAImpl) VerifySignature(hash []byte, sig *Signature, pubKey *PublicKey) (bool, error) {
	r, s := sig.R, sig.S
	if !e.Curve.IsValidScalar(r) || !e.Curve.IsValidScalar(s) {
		return false, nil
	}
	// w = modInv(s, c.N)
	w := new(big.Int).Set(s)
	w = w.ModInverse(w, e.Curve.N)
	// u1 = mod(hash * w, c.N)
	u1 := new(big.Int).SetBytes(hash)
	u1 = u1.Mul(u1, w)
	u1 = u1.Mod(u1, e.Curve.N)
	// u2 = mod(r * w, c.N)
	u2 := new(big.Int).Set(r)
	u2 = u2.Mul(u2, w)
	u2 = u2.Mod(u2, e.Curve.N)
	// p = u1 * G + u2 * Q
	t0, err := e.Curve.ScalarBaseMultiplyPoint(u1)
	if err != nil {
		return false, err
	}
	t1, err := e.Curve.ScalarMultiplyPoint(pubKey.P, u2)
	if err != nil {
		return false, err
	}
	p, err := e.Curve.AddPoints(t0, t1)
	if err != nil {
		return false, err
	}
	// r = mod(p.X, c.N) ?
	pX := new(big.Int).Set(p.X)
	pX = pX.Mod(pX, e.Curve.N)
	return r.Cmp(pX) == 0, nil
}
