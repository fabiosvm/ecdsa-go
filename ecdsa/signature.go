package ecdsa

import (
	"encoding/hex"
	"math/big"
)

type Signature struct {
	R, S *big.Int
}

func NewSignature(r, s *big.Int) *Signature {
	return &Signature{
		R: r,
		S: s,
	}
}

func NewSignatureFromBytes(bytes []byte) *Signature {
	n := len(bytes) / 2
	rBytes, sBytes := bytes[:n], bytes[n:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	return NewSignature(r, s)
}

func NewSignatureFromString(str string) (*Signature, error) {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return NewSignatureFromBytes(bytes), nil
}

func (s *Signature) Bytes() []byte {
	rBytes, sBytes := s.R.Bytes(), s.S.Bytes()
	n := len(s.R.Bytes())
	bytes := make([]byte, n*2)
	copy(bytes[:n], rBytes)
	copy(bytes[n:], sBytes)
	return bytes
}

func (s *Signature) String() string {
	return hex.EncodeToString(s.Bytes())
}
