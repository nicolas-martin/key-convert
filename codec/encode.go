package codec

import (
	"crypto/elliptic"
	"encoding/asn1"

	"github.com/btcsuite/btcd/btcec"
)

func EncodeECPubKey(pubKey *btcec.PublicKey) ([]byte, error) {
	curve := btcec.S256()
	point := pubKey.ToECDSA()
	return asn1.Marshal(ECPubKey{
		Metadata: []asn1.ObjectIdentifier{
			asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			Secp256k1(),
		},
		PublicKey: asn1.BitString{
			Bytes: elliptic.Marshal(curve, point.X, point.Y),
		},
	})
}

type ECPubKey struct {
	Metadata  []asn1.ObjectIdentifier
	PublicKey asn1.BitString
}

func Secp256k1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 132, 0, 10}
}
