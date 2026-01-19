package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// Encrypt encrypts a string using AES-GCM and the master key from .env
func Encrypt(plainText string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create a unique nonce for this specific encryption
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the nonce to the beginning of the ciphertext
	// This way, we only need to store one string in the DB
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	return hex.EncodeToString(cipherText), nil
}

// Decrypt takes the hex string from the DB and returns the original secret
func Decrypt(cipherTextHex string) (string, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))

	data, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// Split the nonce and the actual ciphertext
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", errors.New("decryption failed (wrong key or tampered data)")
	}

	return string(plainText), nil
}
