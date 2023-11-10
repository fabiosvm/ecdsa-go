package ecdsa

import (
	elliptic "github.com/fabiosvm/ecdsa-go/elliptic"
)

type PublicKey struct {
	P *elliptic.Point
}

func NewPublicKey(p *elliptic.Point) *PublicKey {
	return &PublicKey{
		P: p,
	}
}

func NewPublicKeyFromBytes(bytes []byte) *PublicKey {
	p := elliptic.NewPointFromBytes(bytes)
	return NewPublicKey(p)
}

func NewPublicKeyFromString(str string) (*PublicKey, error) {
	p, err := elliptic.NewPointFromString(str)
	if err != nil {
		return nil, err
	}
	return NewPublicKey(p), nil
}

func (p *PublicKey) Bytes() []byte {
	return p.P.Bytes()
}

func (p *PublicKey) String() string {
	return p.P.String()
}
