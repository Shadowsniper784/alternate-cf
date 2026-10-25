package warp

// The helpers below replicate the module-internal helpers of usque
// (github.com/Diniboy1123/usque, MIT License, Copyright (c) 2025 Diniboy1123),
// which cannot be imported across module boundaries.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"time"
)

// GenerateEcKeyPair creates the client's ECDSA P-256 key pair, returning the
// DER-marshalled private key and PKIX-marshalled public key.
func GenerateEcKeyPair() ([]byte, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	marshalledPrivKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, err
	}

	marshalledPubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return marshalledPrivKey, marshalledPubKey, nil
}

// GenerateCert builds the self-signed certificate presented to the MASQUE
// endpoint during the client-certificate handshake.
func GenerateCert(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, &x509.Certificate{}, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	return [][]byte{cert}, nil
}

// ParseEcPrivateKey decodes the stored base64-encoded DER private key.
func ParseEcPrivateKey(b64 string) (*ecdsa.PrivateKey, error) {
	der, err := decodeBase64(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(der)
}

// ParseEndpointPublicKey decodes the PEM-encoded endpoint public key that the
// registration returned (used for certificate pinning).
func ParseEndpointPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pemDecode([]byte(pemStr))
	if block == nil {
		return nil, errBadEndpointKey
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errBadEndpointKey
	}
	return ecPub, nil
}
