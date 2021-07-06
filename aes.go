package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"
)

// TTLMessage struct for time to live message
type TTLMessage struct {
	Message string `json:"message"`
	TTL     int64  `json:"ttl"`
}

// AasaamAES is encryption decryption
type AasaamAES struct {
	key []byte
}

// GenerateKey Base64 encoded random bytes with length 32
func GenerateKey() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic(err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// NewAasaamAES Create instance
func NewAasaamAES(key string) *AasaamAES {
	byteKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		panic(err.Error())
	}
	aes := AasaamAES{key: byteKey}
	return &aes
}

// EncryptTTL Encrypt message with time to live
func (a *AasaamAES) EncryptTTL(message string, ttl int64) string {
	ttlMessage := TTLMessage{Message: message, TTL: time.Now().Unix() + ttl}
	jsonMessage, _ := json.Marshal(ttlMessage)
	return a.Encrypt(string(jsonMessage))
}

// DecryptTTL Decrypted message that contain time to liv
// return Original message or empty string on failure
func (a *AasaamAES) DecryptTTL(encryptedTTLMessage string) string {
	jsonMessage := a.Decrypt(encryptedTTLMessage)
	if jsonMessage == "" {
		return ""
	}
	var ttlMessage TTLMessage
	err := json.Unmarshal([]byte(jsonMessage), &ttlMessage)
	if err != nil {
		return ""
	}
	if ttlMessage.TTL >= time.Now().Unix() {
		return ttlMessage.Message
	}
	return ""
}

// Encrypt Encrypt message
func (a *AasaamAES) Encrypt(message string) string {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		panic(err.Error())
	}
	iv := make([]byte, 12)

	_, eio := io.ReadFull(rand.Reader, iv)
	if eio != nil {
		panic(eio.Error())
	}

	aes, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	encrypted := aes.Seal(nil, iv, []byte(message), nil)
	data := base64.StdEncoding.EncodeToString(append(iv, encrypted...))
	return data
}

// Decrypt Decrypt message
// return Original message or empty string on failure
func (a *AasaamAES) Decrypt(message string) string {
	packet, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return ""
	}
	iv := packet[:12]
	encrypted := packet[12:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return ""
	}
	aes, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	plaintext, err := aes.Open(nil, iv, encrypted, nil)
	if err != nil {
		return ""
	}
	return string(plaintext)
}
