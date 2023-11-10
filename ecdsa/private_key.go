package ecdsa

import (
	"encoding/hex"
	"math/big"
)

type PrivateKey struct {
	D *big.Int
}

func NewPrivateKey(d *big.Int) *PrivateKey {
	return &PrivateKey{
		D: d,
	}
}

func NewPrivateKeyFromBytes(bytes []byte) *PrivateKey {
	d := new(big.Int).SetBytes(bytes)
	return NewPrivateKey(d)
}

func NewPrivateKeyFromString(str string) (*PrivateKey, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return NewPrivateKeyFromBytes(bytes), nil
}

func (p *PrivateKey) Bytes() []byte {
	return p.D.Bytes()
}

func (p *PrivateKey) String() string {
	return hex.EncodeToString(p.Bytes())
}
