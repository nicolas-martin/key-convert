package account

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/nicolas-martin/key-convert/codec"
	"github.com/stretchr/testify/assert"
)

func TestFromECPubKey(t *testing.T) {
	icpAccountID := &accountId{data: []byte("02f2326544f2040d3985e31db5e7021402c541d3cde911cd20e951852ee4da47")}

	rawPk, err := hex.DecodeString("04931f4d17682b3dedbbd87d29d86040ee5f361a182045c3475ff2fc05af7e30a79f1040784655b226520dbb71aac3edc951cd50a64c138596ef746265e4cf122f")
	assert.NoError(t, err)

	pk, err := btcec.ParsePubKey(rawPk, btcec.S256())
	assert.NoError(t, err)

	got, err := FromECPubKey(pk)
	assert.Nil(t, err)
	fmt.Printf("%s\n", got.String())
	fmt.Printf("%s\n", icpAccountID.data)
	assert.Equal(t, string(icpAccountID.data), got.String())
}

func TestEncodePubKey(t *testing.T) {
	rawPk, err := hex.DecodeString("04931f4d17682b3dedbbd87d29d86040ee5f361a182045c3475ff2fc05af7e30a79f1040784655b226520dbb71aac3edc951cd50a64c138596ef746265e4cf122f")
	assert.NoError(t, err)

	pubKey, err := btcec.ParsePubKey(rawPk, btcec.S256())
	assert.NoError(t, err)

	curve := btcec.S256()
	point := pubKey.ToECDSA()

	elliptic := elliptic.Marshal(curve, point.X, point.Y)
	fmt.Printf("%x\n", elliptic)
	// Output: 04931f4d17682b3dedbbd87d29d86040ee5f361a182045c3475ff2fc05af7e30a79f1040784655b226520dbb71aac3edc951cd50a64c138596ef746265e4cf122f

	ellipTicbitString := asn1.BitString{Bytes: elliptic}

	ecppubkey := codec.ECPubKey{
		Metadata: []asn1.ObjectIdentifier{
			asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			asn1.ObjectIdentifier{1, 3, 132, 0, 10},
		},
		PublicKey: ellipTicbitString,
	}
	bEcppubkey, _ := json.Marshal(ecppubkey)
	fmt.Println(string(bEcppubkey))
	// Output: {"Metadata":[[1,2,840,10045,2,1],[1,3,132,0,10]],"PublicKey":{"Bytes":"BJMfTRdoKz3tu9h9KdhgQO5fNhoYIEXDR1/y/AWvfjCnnxBAeEZVsiZSDbtxqsPtyVHNUKZME4WW73RiZeTPEi8=","BitLength":0}}

	marshalledKey, err := asn1.Marshal(ecppubkey)
	assert.NoError(t, err)
	jsonMarshalledKey, _ := json.Marshal(marshalledKey)
	fmt.Println(string(jsonMarshalledKey))
	// Output: "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEkx9NF2grPe272H0p2GBA7l82GhggRcNHX/L8Ba9+MKefEEB4RlWyJlINu3Gqw+3JUc1QpkwThZbvdGJl5M8SLw=="
}

func TestRestEncode(t *testing.T) {
	rawPk, err := hex.DecodeString("04931f4d17682b3dedbbd87d29d86040ee5f361a182045c3475ff2fc05af7e30a79f1040784655b226520dbb71aac3edc951cd50a64c138596ef746265e4cf122f")
	assert.NoError(t, err)

	pubKey, err := btcec.ParsePubKey(rawPk, btcec.S256())
	assert.NoError(t, err)

	der, err := codec.EncodeECPubKey(pubKey)
	assert.NoError(t, err)
	selfId := NewSelfAuthenticatingId(der)
	fmt.Printf("%s\n", selfId)
	// Output: tjpnz-kfh3h-es2ok-k7wp4-ieiad-qvntd-hd4k3-zxdlf-tg3of-l37zo-7ae

	hash := sha256.New224()
	hash.Write([]byte("\x0Aaccount-id"))
	hash.Write(selfId.Bytes())
	hash.Write(make([]byte, 32))
	data := hash.Sum(nil)
	d := &accountId{data: data}

	fmt.Printf("%s\n", d.String())
	// Output: 02f2326544f2040d3985e31db5e7021402c541d3cde911cd20e951852ee4da47

}
