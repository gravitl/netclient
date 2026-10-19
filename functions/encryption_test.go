package functions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestDeriveSharedKeySymmetric(t *testing.T) {
	serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostPub, hostPriv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyFromHost, err := DeriveSharedKey(hostPriv, serverPub)
	require.NoError(t, err)
	keyFromServer, err := DeriveSharedKey(serverPriv, hostPub)
	require.NoError(t, err)

	assert.Equal(t, keyFromServer, keyFromHost, "server and host must derive the identical key")
	assert.Len(t, keyFromHost, 32)
}

func TestDeriveSharedKeyDiffersFromRawPublicKey(t *testing.T) {
	hostPub, hostPriv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	serverPub, _, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	derived, err := DeriveSharedKey(hostPriv, serverPub)
	require.NoError(t, err)

	assert.NotEqual(t, hostPub[:], derived)
	assert.NotEqual(t, serverPub[:], derived)
}

// TestDeriveSharedKeyAESGCMRoundtrip exercises the derived key the way
// publish()/decryptServerMsg actually use it: encrypt with AES-GCM using one
// side's derived key, decrypt with the other side's.
func TestDeriveSharedKeyAESGCMRoundtrip(t *testing.T) {
	serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)
	hostPub, hostPriv, err := box.GenerateKey(rand.Reader)
	require.NoError(t, err)

	serverKey, err := DeriveSharedKey(serverPriv, hostPub)
	require.NoError(t, err)
	hostKey, err := DeriveSharedKey(hostPriv, serverPub)
	require.NoError(t, err)
	require.Equal(t, serverKey, hostKey)

	plaintext := []byte("hello from server")
	block, err := aes.NewCipher(serverKey)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	decrypted, err := decryptAESGCM(hostKey, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptAESGCMRejectsShortCiphertext(t *testing.T) {
	key := make([]byte, 32)
	_, err := decryptAESGCM(key, []byte("short"))
	require.Error(t, err)
}
