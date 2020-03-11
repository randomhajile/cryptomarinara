package cryptomarinara

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/suite"
)

type CipherTestSuite struct {
	suite.Suite
	cipher *Cipher
	key    string
	str    string
}

func (suite *CipherTestSuite) SetupTest() {
	suite.key = "95D38DA1026DE732668FC5B275CBA34FFCE8C3C7ED8BBD5EE50A241C7681171B"
	suite.cipher, _ = NewFromHexString(suite.key) // nolint: errcheck
	suite.str = "this is a secret message"
}

func TestCipherTestSuite(t *testing.T) {
	suite.Run(t, new(CipherTestSuite))
}

func (suite *CipherTestSuite) TestNewFromHexString() {
	cipher, err := NewFromHexString(suite.key)

	suite.NotNil(cipher)
	suite.NoError(err)
}

func (suite *CipherTestSuite) TestNewFromHexStringLengthError() {
	key := suite.key[:len(suite.key)-2]
	cipher, err := NewFromHexString(key)

	suite.Nil(cipher)
	suite.EqualError(err, "incorrect key byte length: expected 32 got 31")
}

func (suite *CipherTestSuite) TestNewFromHexStringBadInput() {
	key := suite.key[:len(suite.key)-1] + "x"
	cipher, err := NewFromHexString(key)

	suite.Nil(cipher)
	suite.EqualError(err, "encoding/hex: invalid byte: U+0078 'x'")
}

func (suite *CipherTestSuite) TestNewFromByteSlice() {
	b, _ := hex.DecodeString(suite.key) // nolint: errcheck
	cipher, err := NewFromBytes(b)

	suite.NotNil(cipher)
	suite.NoError(err)
}

func (suite *CipherTestSuite) TestNewFromBytesLengthError() {
	key := suite.key[:len(suite.key)-1]
	b, _ := hex.DecodeString(key) // nolint: errcheck
	cipher, err := NewFromBytes(b)

	suite.Nil(cipher)
	suite.EqualError(err, "incorrect key byte length: expected 32 got 31")
}

func (suite *CipherTestSuite) TestEncryptDecrypt() {
	strBytes := []byte(suite.str)
	encrypted, encryptErr := suite.cipher.Encrypt(strBytes)
	decrypted, decryptErr := suite.cipher.Decrypt(encrypted)

	suite.Nil(encryptErr)
	suite.Nil(decryptErr)
	suite.Equal(strBytes, decrypted)
}

func (suite *CipherTestSuite) TestEncryptStringDecrypt() {
	encrypted, encryptErr := suite.cipher.EncryptString(suite.str)
	decrypted, decryptErr := suite.cipher.Decrypt(encrypted)
	decryptedStr := string(decrypted)

	suite.Nil(encryptErr)
	suite.Nil(decryptErr)
	suite.Equal(suite.str, decryptedStr)
}

func (suite *CipherTestSuite) TestEncryptStringDecryptHexString() {
	encrypted, encryptErr := suite.cipher.EncryptString(suite.str)
	encryptedStr := hex.EncodeToString(encrypted)
	decrypted, decryptErr := suite.cipher.DecryptHexString(encryptedStr)
	decryptedStr := string(decrypted)

	suite.Nil(encryptErr)
	suite.Nil(decryptErr)
	suite.Equal(suite.str, decryptedStr)
}

func (suite *CipherTestSuite) TestDecryptHexStringBadInput() {
	decrypted, err := suite.cipher.DecryptHexString("x")

	suite.Empty(decrypted)
	suite.EqualError(err, "encoding/hex: invalid byte: U+0078 'x'")
}
