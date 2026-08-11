package asm

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"cyberstrike-ai/internal/database"

	"go.uber.org/zap"
)

func TestASMResourceCredentialIsEncryptedAndRedacted(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "conversations.db")
	db, err := database.NewDB(databasePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	service, err := NewService(db, databasePath, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	secret := "test-only-secret-value"
	view, err := service.CreateResource(CreateResourceInput{
		Name: "encrypted ARL", Provider: ProviderARL, BaseURL: "https://asm.example.test",
		Username: "operator", Credential: secret, AuthType: "password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !view.HasCredential {
		t.Fatal("resource view did not report an encrypted credential")
	}
	rawView, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawView), secret) {
		t.Fatal("resource view exposed the credential")
	}

	stored, err := db.GetASMResource(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SecretCiphertext == "" || stored.SecretCiphertext == secret || !strings.HasPrefix(stored.SecretCiphertext, "v1:") {
		t.Fatalf("credential was not stored as versioned ciphertext: %q", stored.SecretCiphertext)
	}
	plain, err := service.cipher.decrypt(view.ID, stored.SecretCiphertext)
	if err != nil || plain != secret {
		t.Fatalf("decrypt credential: plain=%q err=%v", plain, err)
	}
	if _, err := service.cipher.decrypt("another-resource", stored.SecretCiphertext); err == nil {
		t.Fatal("ciphertext decrypted under a different resource AAD")
	}
}
