package aes

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

type Test struct {
	Key          string `json:"key"`
	Message      string `json:"message"`
	Encrypted    string `json:"encrypted"`
	EncryptedTTL string `json:"encryptedTTL"`
	NetworkData  string `json:"networkData"`
}

func TestGenerateKey(t *testing.T) {
	key := GenerateKey()
	if len(key) < 10 || len(key) > 128 {
		t.Errorf("Seems key not generate well")
	}
}

func TestEncryptionDecryption(t *testing.T) {
	key := GenerateKey()
	aes := NewAasaamAES(key)
	message := "Sample message"
	encrypted := aes.EncryptTTL(message, 1)
	if encrypted == "" {
		t.Errorf("Encryption failed")
	}
	sameMessage := aes.DecryptTTL(encrypted)
	if sameMessage != message {
		t.Errorf("Decryption failed")
	}
	time.Sleep(time.Second * 2)
	expiredMessage := aes.DecryptTTL(encrypted)
	if expiredMessage != "" {
		t.Errorf("DecryptionTTL failed")
	}
}

func TestDecryptionFailed(t *testing.T) {
	key1 := GenerateKey()
	key2 := GenerateKey()
	aes1 := NewAasaamAES(key1)
	aes2 := NewAasaamAES(key2)
	message := "Sample message"
	encrypted1 := aes1.Encrypt(message)
	decrypted2 := aes2.Decrypt(encrypted1)
	decrypted3 := aes2.DecryptTTL(encrypted1)
	if decrypted2 != "" {
		t.Errorf("Decryption must failed")
	}
	if decrypted3 != "" {
		t.Errorf("Decryption must failed")
	}
}

func TestEncryptionDecryptionCross(t *testing.T) {
	jsonFile, _ := os.Open("./test.json")
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var test Test
	err := json.Unmarshal(byteValue, &test)
	if err != nil {
		t.Error(err)
	}
	aes := NewAasaamAES(test.Key)
	sameMessage := aes.Decrypt(test.Encrypted)
	if sameMessage != test.Message {
		t.Errorf("Cross language Decryption failed")
	}
	sameMessageTTL := aes.DecryptTTL(test.EncryptedTTL)
	if sameMessageTTL != test.Message {
		t.Errorf("Cross language Decryption failed")
	}
}

func TestClientHash(t *testing.T) {
	jsonFile, _ := os.Open("./test.json")
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var test Test
	err := json.Unmarshal(byteValue, &test)
	if err != nil {
		t.Error(err)
	}

	clientDataSender := []string{"1.1.1.1", "user-agent"}

	clientDataSenderKey := GenerateHashKey(test.Key, clientDataSender)

	aes := NewAasaamAES(clientDataSenderKey)
	sameMessage := aes.Decrypt(test.NetworkData)
	if sameMessage != test.Message {
		t.Errorf("Cross language Decryption failed")
	}
}
