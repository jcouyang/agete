package main

import (
	"testing"
)

func TestAgeKey(t *testing.T) {
	key, _ := GenerateIdentity()
		
	encrypted, e := Encrypt(EncryptReq{
		Recipients: []string{key.PublicKey},
		Binary:      false,
		Content:    "hello",
		Passphrase: "",
	})

	decrypted, e := Decrypt(DecryptReq{
		Identities: []string{key.PrivateKey},
		Binary:      false,
		Content:    encrypted.Content,
		Passphrase: "",
	})
	if decrypted.Content != "hello" || e != nil {
		t.Errorf("expected \"hello\" got %s, error %v", decrypted.Content, e)
	}
}

func TestPass(t *testing.T) {
	pass := GeneratePassphrase()
		
	encrypted, e := Encrypt(EncryptReq{
		Recipients: []string{},
		Binary:      false,
		Content:    "hello",
		Passphrase: pass,
	})

	decrypted, e := Decrypt(DecryptReq{
		Identities: []string{},
		Binary:      false,
		Content:    encrypted.Content,
		Passphrase: pass,
	})
	if decrypted.Content != "hello" || e != nil {
		t.Errorf("expected \"hello\" got %s, error %v", decrypted.Content, e)
	}
}
