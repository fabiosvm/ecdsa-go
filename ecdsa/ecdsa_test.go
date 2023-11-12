package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	cryptoElliptic "crypto/elliptic"

	elliptic "github.com/fabiosvm/ecdsa-go/elliptic"
)

func TestPrivateKeyIsValid(t *testing.T) {
	ec := NewECDSA(elliptic.Secp256r1)

	cryptoPrivKey, err := ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	privKey := NewPrivateKey(cryptoPrivKey.D)

	if !ec.PrivateKeyIsValid(privKey) {
		t.Error("Expected private key to be valid.")
	}
}

func TestPublicKeyIsValid(t *testing.T) {
	ec := NewECDSA(elliptic.Secp256r1)

	cryptoPrivKey, err := ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	cryptoPublicKey := cryptoPrivKey.PublicKey

	pubKey := NewPublicKey(elliptic.NewPoint(cryptoPublicKey.X, cryptoPublicKey.Y))

	if !ec.PublicKeyIsValid(pubKey) {
		t.Error("Expected public key to be valid.")
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	ec := NewECDSA(elliptic.Secp256r1)

	privKey, err := ec.GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	if !ec.PrivateKeyIsValid(privKey) {
		t.Error("Expected private key to be valid.")
	}
}

func TestPublicKey(t *testing.T) {
	ec := NewECDSA(elliptic.Secp256r1)

	cryptoPrivKey, err := ecdsa.GenerateKey(cryptoElliptic.P256(), rand.Reader)
	if err != nil {
		t.Error(err)
	}

	cryptoPublicKey := cryptoPrivKey.PublicKey

	privKey := NewPrivateKey(cryptoPrivKey.D)

	pubKey, err := ec.PublicKey(privKey)
	if err != nil {
		t.Error(err)
	}

	if !ec.PublicKeyIsValid(pubKey) {
		t.Error("Expected public key to be valid.")
	}

	if pubKey.P.X.Cmp(cryptoPublicKey.X) != 0 {
		t.Error("Expected public key X to be equal.")
	}

	if pubKey.P.Y.Cmp(cryptoPublicKey.Y) != 0 {
		t.Error("Expected public key Y to be equal.")
	}
}

func TestSignAndVerifySignature(t *testing.T) {
	ec := NewECDSA(elliptic.Secp256r1)

	privKey, err := ec.GeneratePrivateKey(rand.Reader)
	if err != nil {
		t.Error(err)
	}

	pubKey, err := ec.PublicKey(privKey)
	if err != nil {
		t.Error(err)
	}

	hash := sha256.Sum256([]byte("foo"))

	sig, err := ec.Sign(hash[:], privKey, rand.Reader)
	if err != nil {
		t.Error(err)
	}

	ok := ec.VerifySignature(hash[:], sig, pubKey)
	if !ok {
		t.Error("Expected signature to be valid.")
	}
}
