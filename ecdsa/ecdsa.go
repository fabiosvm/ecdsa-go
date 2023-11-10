package ecdsa

import (
	"io"
)

type ECDSA interface {
	PrivateKeyIsValid(privKey *PrivateKey) bool
	PublicKeyIsValid(pubKey *PublicKey) bool
	GeneratePrivateKey(rand io.Reader) (*PrivateKey, error)
	PublicKey(privKey *PrivateKey) (*PublicKey, error)
	Sign(hash []byte, privKey *PrivateKey, rand io.Reader) (*Signature, error)
	VerifySignature(hash []byte, sig *Signature, pubKey *PublicKey) (bool, error)
}
