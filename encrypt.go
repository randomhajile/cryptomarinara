package cryptomarinara

import (
	"encoding/hex"
	"fmt"

	"github.com/gtank/cryptopasta"
)

// Cipher struct for storing encryption key and wrapping it for encryption/decryption.
type Cipher struct {
	key *[32]byte
}

// NewFromHexString initializes a new Cipher using a hex string
func NewFromHexString(s string) (*Cipher, error) {
	keyByteSlice, decodeErr := hex.DecodeString(s)
	if decodeErr != nil {
		return nil, decodeErr
	} else if l := len(keyByteSlice); l != 32 {
		return nil, fmt.Errorf("incorrect key byte length: expected 32 got %d", l)
	}

	keyBytes := [32]byte{}
	copy(keyBytes[:], keyByteSlice)
	return &Cipher{key: &keyBytes}, nil
}

// NewFromBytes initializes a new Cipher using a byte slice.
func NewFromBytes(b []byte) (*Cipher, error) {
	if l := len(b); l != 32 {
		return nil, fmt.Errorf("incorrect key byte length: expected 32 got %d", l)
	}

	keyBytes := [32]byte{}
	copy(keyBytes[:], b)
	return &Cipher{key: &keyBytes}, nil
}

// EncryptString convenience method to Encrypt
func (c *Cipher) EncryptString(plaintext string) ([]byte, error) {
	return c.Encrypt([]byte(plaintext))
}

// Encrypt the given plaintext.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	return cryptopasta.Encrypt(plaintext, c.key)
}

// DecryptHexString convenience method.
// This method expects the encrypted string to have been hex encoded.
func (c *Cipher) DecryptHexString(ciphertext string) ([]byte, error) {
	bytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	return cryptopasta.Decrypt(bytes, c.key)
}

// Decrypt wrapper for decrypting using the globally defined key.
func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	return cryptopasta.Decrypt(ciphertext, c.key)
}
