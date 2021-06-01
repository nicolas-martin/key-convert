package account

import (
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

func TestFromECPubKey(t *testing.T) {
	accountID := accountId{data: []byte("02f2326544f2040d3985e31db5e7021402c541d3cde911cd20e951852ee4da47")}

	rawPk, _ := hex.DecodeString("04931f4d17682b3dedbbd87d29d86040ee5f361a182045c3475ff2fc05af7e30a79f1040784655b226520dbb71aac3edc951cd50a64c138596ef746265e4cf122f")
	pk, err := btcec.ParsePubKey(rawPk, btcec.S256())
	assert.Nil(t, err)

	got, err := FromECPubKey(pk)
	assert.Nil(t, err)
	assert.Equal(t, got, accountID)
}
