package account

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/dfinity/keysmith/codec"
)

type AccountId interface {
	String() string
}

type accountId struct {
	data []byte
}

func FromECPubKey(pubKey *btcec.PublicKey) (AccountId, error) {
	der, err := codec.EncodeECPubKey(pubKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.New224()
	hash.Write([]byte("\x0Aaccount-id"))
	hash.Write(NewSelfAuthenticatingId(der).Bytes())
	hash.Write(make([]byte, 32))
	data := hash.Sum(nil)
	return &accountId{data: data}, nil
}

func (accountId *accountId) String() string {
	crc := make([]byte, 4)
	binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(accountId.data))
	return hex.EncodeToString(append(crc, accountId.data...))
}

func NewSelfAuthenticatingId(der []byte) PrincipalId {
	hash := sha256.Sum224(der)
	data := append(hash[:], []byte{2}...)
	return &SelfAuthenticatingId{data: data}
}

type PrincipalId interface {
	Bytes() []byte
	String() string
}

type SelfAuthenticatingId struct {
	data []byte
}

func (principalId *SelfAuthenticatingId) Bytes() []byte {
	return principalId.data
}

func (principalId *SelfAuthenticatingId) String() string {
	return show(principalId.data)
}

func show(data []byte) string {
	crc := make([]byte, 4)
	binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(data))
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	str := encoder.EncodeToString(append(crc, data...))
	return strings.Join(split(strings.ToLower(str), 5), "-")
}

func split(str string, n int) []string {
	if n >= len(str) {
		return []string{str}
	}
	var chunks []string
	chunk := make([]rune, n)
	i := 0
	for _, r := range str {
		chunk[i] = r
		i++
		if i == n {
			chunks = append(chunks, string(chunk))
			i = 0
		}
	}
	if i > 0 {
		chunks = append(chunks, string(chunk[:i]))
	}
	return chunks
}
