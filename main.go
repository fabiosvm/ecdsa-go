package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	ecdsa "github.com/fabiosvm/ecdsa-go/ecdsa"
	elliptic "github.com/fabiosvm/ecdsa-go/elliptic"
)

func main() {
	ec := ecdsa.NewECDSA(elliptic.Secp256k1)

	// Generate a private key
	privKey, err := ec.GeneratePrivateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating private key: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private key: %s\n", privKey.String())

	// Generate the corresponding public key
	pubKey, err := ec.PublicKey(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating public key: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Public key: %s\n", pubKey.String())

	// Compress the public key
	compressedPubKey, err := ec.CompressPublicKey(pubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error compressing public key: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Compressed public key: %s\n", hex.EncodeToString(compressedPubKey))

	// Decompress the public key
	decompressedPubKey, err := ec.DecompressPublicKey(compressedPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decompressing public key: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Decompressed public key: %s\n", decompressedPubKey.String())

	// Generate the hash of a message
	hash := sha256.Sum256([]byte("foo"))
	fmt.Printf("Hash: %s\n", hex.EncodeToString(hash[:]))

	// Sign the hash
	sig, err := ec.Sign(hash[:], privKey, rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing hash: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Signature: %s\n", sig.String())

	// Verify the signature
	ok := ec.VerifySignature(hash[:], sig, pubKey)
	if ok {
		fmt.Println("Wow! Signature is valid.")
	} else {
		fmt.Println("Oh no! Signature is invalid.")
	}
}
